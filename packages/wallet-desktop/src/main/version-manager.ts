import { get, RequestOptions } from 'https'

import { Locals } from './internal'

export class VersionManager {
  latestVersion: string
  currentVersion: string
  initialized: Promise<void>

  constructor (protected locals: Locals) {
    this.currentVersion = `v${locals.packageJson.version}`
    this.latestVersion = ''
    this.initialized = new Promise((resolve, reject) => {
      this.initialize().then(() => {
        resolve()
      }).catch((reason) => {
        reject(reason)
      })
    })
  }

  async initialize (): Promise<void> {
    const lastestVersionInfoUrl = 'https://api.github.com/repos/i3-Market-V2-Public-Repository/SP3-SCGBSSW-I3mWalletMonorepo/releases/latest'
    try {
      this.latestVersion = (await this.getRemoteJson(lastestVersionInfoUrl)).tag_name 
    } catch (error) {
      this.latestVersion = this.currentVersion
      throw new Error('Could not retrieve latest published i3M-Wallet app version. Please check your internet connection')
    }
  }

  async getRemoteJson (url: string): Promise<any> {
    await this.initialized
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

  async needsUpdate (): Promise<boolean> {
    await this.initialized
    const currentVersion = this.parseVersion(this.currentVersion)
    const latestVersion = this.parseVersion(this.latestVersion)

    if (currentVersion.length !== latestVersion.length) {
      throw new Error('Inconsistent versions')
    }

    for (let i = 0; i < currentVersion.length; i++) {
      if (currentVersion[i] < latestVersion[i]) {
        return true
      }
    }

    return false
  }
}
