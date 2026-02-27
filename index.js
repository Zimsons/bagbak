import { EventEmitter } from 'events';
import { mkdir, rm, rmdir, rename, open } from 'fs/promises';
import { basename, join, resolve } from 'path';

import chalk from 'chalk';

import { AppBundleVisitor } from './lib/scan.js';
import { MH_EXECUTE } from './lib/macho.js';
import { Pull } from './lib/scp.js';
import { connect } from './lib/ssh.js';
import { debug, directoryExists, readFromPackage } from './lib/utils.js';
import zip from './lib/zip.js';

/**
 * @typedef {Object} MessagePayload
 * @property {string} event
 * @property {string} name
 * @property {number} fileOffset
 */

/**
 * @typedef {Object} ExtensionInfo
 * @property {string} id
 * @property {string} path
 */

/**
 * @typedef {Object} MachOInfo
 * @property {string} type
 * @property {number} offset
 * @property {number} size
 */

/**
 * main class
 */
export class BagBak extends EventEmitter {
  /** @type {import("frida").Device} */
  #device;

  /** @type {import("frida").Application | null} */
  #app = null;

  /** @type {import("ssh2").ConnectConfig} */
  #auth;

  /** @type {AbortController | null} */
  #abortController = null;

  /**
   * constructor
   * @param {import("frida").Device} device 
   * @param {import("frida").Application} app
   */
  constructor(device, app) {
    super();
    this.#app = app;
    this.#device = device;
    this.#setupAuth();
  }

  /**
   * Setup authentication configuration
   * @private
   */
  #setupAuth() {
    if ('SSH_USERNAME' in process.env || 'SSH_PASSWORD' in process.env) {
      const { SSH_USERNAME, SSH_PASSWORD } = process.env;
      if (!SSH_USERNAME || !SSH_PASSWORD) {
        throw new Error('You have to provide both SSH_USERNAME and SSH_PASSWORD');
      }

      this.#auth = {
        username: SSH_USERNAME,
        password: SSH_PASSWORD
      };
    } else if ('SSH_PRIVATE_KEY' in process.env) {
      throw new Error('Key authentication not supported yet');
    } else {
      this.#auth = {
        username: 'mobile',
        password: 'alpine'
      };
    }
  }

  /**
   * scp from remote to local
   * @param {string} src 
   * @param {import("fs").PathLike} dest 
   * @returns {Promise<void>}
   */
  async #copyToLocal(src, dest) {
    const client = await connect(this.#device, this.#auth);

    try {
      const pull = new Pull(client, src, dest, true);
      const events = ['download', 'mkdir', 'progress', 'done'];
      
      for (const event of events) {
        pull.receiver.on(event, (...args) => this.emit(event, ...args));
      }

      await pull.execute();
    } finally {
      client.end();
    }
  }

  /**
   * Get bundle identifier
   * @returns {string}
   */
  get bundle() {
    return this.#app?.identifier ?? '';
  }

  /**
   * Get remote path
   * @returns {string}
   */
  get remote() {
    return this.#app?.parameters?.path ?? '';
  }

  /**
   * Create a Frida script with proper error handling
   * @param {number} pid - Process ID
   * @param {string} scriptSource - Script source code
   * @param {Object} options - Script options
   * @returns {Promise<import("frida").Script>}
   */
  async #createScript(pid, scriptSource, options = {}) {
    const session = await this.#device.attach(pid);
    
    // Set up session cleanup
    const abortController = new AbortController();
    this.#abortController = abortController;

    const script = await session.createScript(scriptSource, {
      name: options.name || 'bagbak-script',
      runtime: 'qjs' // Use QuickJS for better performance
    });

    // Modern event handling for Frida 17+
    script.events.listen('message', (message, data) => {
      this.#handleScriptMessage(message, data, options.messageHandler);
    });

    script.events.listen('log', (level, text) => {
      debug('[script log]', level, text);
    });

    // Handle session detachment
    session.events.listen('detached', (reason, crash) => {
      debug('Session detached', { reason, crash });
      abortController.abort();
    });

    return script;
  }

  /**
   * Handle script messages
   * @param {import("frida").Message} message 
   * @param {Buffer} data 
   * @param {Function} messageHandler 
   */
  #handleScriptMessage(message, data, messageHandler) {
    if (message.type === 'error') {
      console.error(chalk.red('Script error:'), message.description);
      return;
    }

    if (message.type === 'send' && messageHandler) {
      messageHandler(message, data);
    }
  }

  /**
   * Dump raw app bundle to directory (no ipa)
   * @param {import("fs").PathLike} parent path
   * @param {boolean} override whether to override existing files
   * @returns {Promise<string>}
   */
  async dump(parent, override = false) {
    if (!await directoryExists(parent)) {
      throw new Error('Output directory does not exist');
    }

    if (!this.#app) {
      throw new Error('No application selected');
    }

    const remoteRoot = this.remote;
    debug('remote root', remoteRoot);
    debug('copy to', parent);

    const localRoot = join(parent, basename(remoteRoot));
    
    if (await directoryExists(localRoot) && !override) {
      throw new Error('Destination already exists, use -f to override');
    }

    this.emit('sshBegin');
    await this.#copyToLocal(remoteRoot, parent);
    this.emit('sshFinish');

    const visitor = new AppBundleVisitor(localRoot);
    await visitor.removeUnwanted();

    /** @type {Map<string, MachOInfo>} */
    const tasks = new Map();
    for await (const [relative, info] of visitor.visitRoot()) {
      tasks.set(relative, info);
    }

    const pidChronod = await this.#getChronodPid();
    
    // Load scripts
    const [agentScript, launchdScript] = await Promise.all([
      readFromPackage('agent', 'inject.js'),
      readFromPackage('agent', 'runningboardd.js')
    ]);

    // Get extensions info
    const extensions = await this.#getExtensionsInfo(launchdScript.toString());
    
    // Group binaries by extension
    const { binariesForMain, groupByExtensions } = await this.#groupBinaries(
      tasks, 
      extensions, 
      remoteRoot
    );

    // Dump main app
    if (Object.keys(binariesForMain).length) {
      await this.#dumpMainApp(binariesForMain, remoteRoot);
    }

    // Dump extensions
    await this.#dumpExtensions(groupByExtensions, pidChronod);

    return localRoot;
  }

  /**
   * Get chronod process ID
   * @returns {Promise<number>}
   */
  async #getChronodPid() {
    try {
      const processes = await this.#device.enumerateProcesses();
      const chronod = processes.find(p => p.name === 'chronod');
      
      if (!chronod) {
        throw new Error(`chronod service is not running on the device.
        Please start it manually with:
        "launchctl kickstart -p user/foreground/com.apple.chronod"`);
      }
      
      return chronod.pid;
    } catch (error) {
      throw new Error(`Failed to get chronod process: ${error.message}`);
    }
  }

  /**
   * Get extensions information
   * @param {string} scriptSource 
   * @returns {Promise<ExtensionInfo[]>}
   */
  async #getExtensionsInfo(scriptSource) {
    const session = await this.#device.attach('runningboardd');
    
    try {
      const script = await session.createScript(scriptSource);
      await script.load();
      
      const extensions = await script.exports.extensions(this.#app?.identifier);
      debug('extensions', extensions);
      
      await script.unload();
      return extensions;
    } finally {
      await session.detach();
    }
  }

  /**
   * Group binaries by extension
   * @param {Map<string, MachOInfo>} tasks 
   * @param {ExtensionInfo[]} extensions 
   * @param {string} remoteRoot 
   * @returns {Promise<{binariesForMain: Record<string, MachOInfo>, groupByExtensions: Map<string, Record<string, MachOInfo>>}>}
   */
  async #groupBinaries(tasks, extensions, remoteRoot) {
    if (!this.#app) {
      throw new Error('No application selected');
    }

    const runningboardd = await this.#device.attach('runningboardd');
    
    try {
      const script = await runningboardd.createScript(`
        rpc.exports = {
          main: function() {
            return "${this.#app.parameters.path}/" + "${basename(this.#app.parameters.path)}";
          }
        };
      `);
      
      await script.load();
      const mainAppBinary = await script.exports.main(this.#app.identifier);
      debug('main app binary', mainAppBinary);

      /** @type {Map<string, Record<string, MachOInfo>>} */
      const groupByExtensions = new Map(extensions.map(ext => [ext.id, {}]));
      /** @type {Record<string, MachOInfo>} */
      const binariesForMain = {};

      for (const [relative, info] of tasks.entries()) {
        const absolute = `${remoteRoot}/${relative}`;
        const ext = extensions.find(e => absolute.startsWith(e.path));
        
        if (ext) {
          debug('scope for', chalk.green(relative), 'is', chalk.gray(ext.id));
          const extBinaries = groupByExtensions.get(ext.id) || {};
          extBinaries[relative] = info;
          groupByExtensions.set(ext.id, extBinaries);
          continue;
        }

        if (info.type === MH_EXECUTE && absolute !== mainAppBinary) {
          console.error(chalk.red('Executable'), chalk.yellowBright(relative));
          console.error(chalk.red('is not within any extension.'));
        } else {
          debug('scope for', relative, 'is', chalk.green('main app'));
          binariesForMain[relative] = info;
        }
      }

      return { binariesForMain, groupByExtensions };
    } finally {
      await runningboardd.detach();
    }
  }

  /**
   * Dump main application
   * @param {Record<string, MachOInfo>} binaries 
   * @param {string} remoteRoot 
   */
  async #dumpMainApp(binaries, remoteRoot) {
    if (!this.#app) return;

    const pid = await this.#spawnApplication(this.#app.identifier);
    await this.#dumpBinaries(pid, binaries, remoteRoot);
  }

  /**
   * Spawn application and return PID
   * @param {string} identifier 
   * @returns {Promise<number>}
   */
  async #spawnApplication(identifier) {
    const pid = await this.#device.spawn([identifier]);
    debug('Spawned app PID:', pid);
    return pid;
  }

  /**
   * Dump binaries for a process
   * @param {number} pid 
   * @param {Record<string, MachOInfo>} binaries 
   * @param {string} remoteRoot 
   */
  async #dumpBinaries(pid, binaries, remoteRoot) {
    const fileHandles = new Map();
    
    const messageHandler = async (message, data) => {
      const payload = /** @type {MessagePayload} */ (message.payload);
      const key = payload.name;
      
      switch (payload.event) {
        case 'begin':
          this.emit('patch', key);
          debug('patch >>', key);
          const fd = await open(key, 'r+');
          fileHandles.set(key, fd);
          break;
          
        case 'trunk':
          const handle = fileHandles.get(key);
          if (handle && data) {
            await handle.write(data, 0, data.byteLength, payload.fileOffset);
          }
          break;
          
        case 'end':
          const fileHandle = fileHandles.get(key);
          if (fileHandle) {
            await fileHandle.close();
            fileHandles.delete(key);
          }
          break;
      }
    };

    const agentScript = await readFromPackage('agent', 'inject.js');
    const script = await this.#createScript(pid, agentScript.toString(), {
      name: `dump-${pid}`,
      messageHandler
    });

    try {
      await script.load();
      const result = await script.exports.dump(remoteRoot, binaries);
      debug('dump result:', result);
    } finally {
      await script.unload();
      const session = script.session;
      if (session) {
        await session.detach();
      }
    }
  }

  /**
   * Dump extensions
   * @param {Map<string, Record<string, MachOInfo>>} extensions 
   * @param {number} pidChronod 
   */
  async #dumpExtensions(extensions, pidChronod) {
    for (const [extId, binaries] of extensions.entries()) {
      if (Object.keys(binaries).length === 0) continue;

      try {
        const pid = await this.#kickstartExtension(extId, pidChronod);
        debug('Extension', extId, 'PID:', pid);
        await this.#dumpBinaries(pid, binaries, this.remote);
      } catch (error) {
        console.error(chalk.red(`Failed to dump extension ${extId}:`), error.message);
      }
    }
  }

  /**
   * Kickstart an extension
   * @param {string} extId 
   * @param {number} pidChronod 
   * @returns {Promise<number>}
   */
  async #kickstartExtension(extId, pidChronod) {
    // Implementation depends on your specific needs
    // This is a placeholder for the actual extension kickstart logic
    throw new Error('Extension kickstart not implemented');
  }

  /**
   * Dump and pack to ipa
   * @param {import("fs").PathLike} suggested path of ipa
   * @returns {Promise<string>} final path of ipa
   */
  async pack(suggested) {
    if (!this.#app) {
      throw new Error('No application selected');
    }

    const DIR_NAME = '.bagbak';
    const payload = join(DIR_NAME, this.bundle, 'Payload');
    
    await rm(payload, { recursive: true, force: true });
    await mkdir(payload, { recursive: true });
    await this.dump(payload, true);
    debug('payload =>', payload);

    const ver = this.#app.parameters?.version || 'Unknown';
    const defaultTemplate = `${this.bundle}-${ver}.ipa`;

    const ipa = suggested ?
      (await directoryExists(suggested) ?
        join(suggested, defaultTemplate) :
        suggested) :
      defaultTemplate;

    if (!ipa.endsWith('.ipa')) {
      throw new Error(`Invalid archive name ${suggested}, must end with .ipa`);
    }

    const full = resolve(process.cwd(), ipa);
    const z = full.slice(0, -4) + '.zip';
    
    await zip(z, payload);
    debug('Created zip archive', z);
    await rename(z, ipa);

    // Cleanup
    await this.#cleanup(DIR_NAME, this.bundle);

    return ipa;
  }

  /**
   * Clean up temporary files
   * @param {string} dirName 
   * @param {string} bundleId 
   */
  async #cleanup(dirName, bundleId) {
    const artifact = join(dirName, bundleId);
    
    try {
      await rm(artifact, { recursive: true, force: true });
    } catch (error) {
      debug(`Warning: failed to remove artifact directory ${artifact}`, error);
    }

    try {
      await rmdir(dirName);
    } catch {
      // Ignore errors if directory isn't empty
    }
  }

  /**
   * Abort current operation
   */
  abort() {
    if (this.#abortController) {
      this.#abortController.abort();
      this.#abortController = null;
    }
  }
}
