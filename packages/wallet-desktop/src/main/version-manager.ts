import { get, RequestOptions } from 'https'

import {
  handlePromise,
  InvalidSettingsError,
  Locals,
  logger,
  MainContext,
  NoConnectionError,
  softwareVersion,
  wait
} from './internal'

interface Props {
  settingsVersion: string
}

export class VersionManager {
  softwareVersion: string
  settingsVersion: string

  static async initialize (ctx: MainContext, locals: Locals): Promise<VersionManager> {
    const publicSettings = locals.storeManager.getStore('public-settings')
    const version = await publicSettings.get('version')

    return new VersionManager(locals, {
      settingsVersion: version
    })
  }

  constructor (protected locals: Locals, props: Props) {
    this.softwareVersion = softwareVersion(locals)
    this.settingsVersion = props.settingsVersion
    this.bindRuntimeEvents()
  }

  bindRuntimeEvents (): void {
    const { runtimeManager } = this.locals

    runtimeManager.on('after-start', async () => {
      await this.verifySettingsVersion()
      // Do not await verifyLatestVersion!
      // If there is no internet connection it will freeze the application
      handlePromise(this.locals, this.verifyLatestVersion())
    })

    runtimeManager.on('after-migration', async () => {
      await this.finishMigration()
    })
  }

  async verifySettingsVersion (): Promise<void> {
    const { settingsVersion, softwareVersion } = this
    if (this.compareVersions(settingsVersion, softwareVersion) > 0) {
      throw new InvalidSettingsError(`Your settings version (${settingsVersion}) is newer than the version of the wallet that you are running now (${softwareVersion}).\n Please, install a newer version of the wallet going to 'Help → Latest Release'.`)
    }
  }

  async verifyLatestVersion (): Promise<void> {
    const lastestVersionInfoUrl = 'https://api.github.com/repos/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo/releases/latest'
    let firstTry = true
    let onlineVersion: string = ''
    while (onlineVersion === '') {
      try {
        onlineVersion = (await this.getRemoteJson(lastestVersionInfoUrl)).tag_name
        break
      } catch (err) {
        if (firstTry) {
          const noConnection = new NoConnectionError('No internet connection')
          noConnection.showToast(this.locals)
          firstTry = false
        }
        // Sleep some time after retry
        await wait(10000)
      }
    }

    if (!firstTry) {
      this.locals.toast.show({
        message: 'Connection established',
        details: 'The connection issue is solved! We can now check if you have the latest version.',
        type: 'success',
        timeout: 3000
      })
    }

    const { softwareVersion: currentVersion } = this
    if (this.compareVersions(onlineVersion, currentVersion) > 0) {
      this.locals.toast.show({
        message: 'Update pending...',
        details: `Your current version (${currentVersion}) is outdated. \n Please, download the latest release (${onlineVersion}) going to 'Help → Latest Release'.`,

        type: 'warning',
        timeout: 0 // never close this alert!
      })
    }
  }

  async getRemoteJson (url: string): Promise<any> {
    return await new Promise((resolve, reject) => {
      const urlObject = new URL(url)
      const opts: RequestOptions = {
        host: urlObject.host,
        port: urlObject.port,
        protocol: urlObject.protocol,
        path: urlObject.pathname,
        headers: { 'User-Agent': 'I3M-Wallet-App' }
      }
      get(opts, (res) => {
        const statusCode = res.statusCode ?? 0
        const contentType = res.headers['content-type'] ?? ''

        let error
        // Any 2xx status code signals a successful response but
        // here we're only checking for 200.
        if (statusCode < 200 || statusCode >= 300) {
          error = new Error('Request Failed.\n' +
                            `Status Code: ${statusCode}`)
        } else if (!/^application\/json/.test(contentType)) {
          error = new Error('Invalid content-type.\n' +
                            `Expected application/json but received ${contentType}`)
        }
        if (error != null) {
          // Consume response data to free up memory
          res.resume()
          reject(error)
          return
        }

        res.setEncoding('utf8')
        let rawData = ''
        res.on('data', (chunk: string) => { rawData += chunk })
        res.on('end', () => {
          try {
            const parsedData = JSON.parse(rawData)
            resolve(parsedData)
          } catch (e) {
            reject(e)
          }
        })
      }).on('error', (e) => {
        reject(e)
      })
    })
  }

  parseVersion (version: string): number[] {
    return version
      .slice(1)
      .split('.')
      .map(n => parseInt(n))
  }

  compareVersions (a: string, b: string): number {
    if (a === b) {
      return 0
    }

    const aVersion = this.parseVersion(a)
    const bVersion = this.parseVersion(b)

    if (aVersion.length !== bVersion.length) {
      throw new Error('Inconsistent versions')
    }

    for (let i = 0; i < aVersion.length; i++) {
      if (aVersion[i] < bVersion[i]) {
        return -1
      }
    }

    return 1
  }

  needsUpdate (onlineVersion: string): boolean {
    const currentVersion = this.parseVersion(this.softwareVersion)
    const latestVersion = this.parseVersion(onlineVersion)

    if (currentVersion.length !== onlineVersion.length) {
      throw new Error('Inconsistent versions')
    }

    for (let i = 0; i < currentVersion.length; i++) {
      if (currentVersion[i] < latestVersion[i]) {
        return true
      }
    }

    return false
  }

  async finishMigration (): Promise<void> {
    const publicSettings = this.locals.storeManager.getStore('public-settings')
    await publicSettings.set('version', this.softwareVersion)
    this.settingsVersion = this.softwareVersion

    logger.debug('Migration finished')
  }
}
