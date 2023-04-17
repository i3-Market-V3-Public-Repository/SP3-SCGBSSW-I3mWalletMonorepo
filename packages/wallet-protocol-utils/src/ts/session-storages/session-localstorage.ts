import type { SessionStorage, SessionLocalStorageOptions } from '../types'

export class SessionLocalStorage implements SessionStorage {
  protected key: string
  constructor (options?: SessionLocalStorageOptions) {
    this.key = (typeof options?.key === 'string' && options.key !== '') ? options.key : 'wallet-session'
  }

  async getSessionData (): Promise<any> {
    const item = localStorage.getItem(this.key)
    if (item == null) {
      throw new Error('no session data stored')
    }
    return JSON.parse(item)
  }

  async setSessionData (json: any): Promise<void> {
    localStorage.setItem(this.key, JSON.stringify(json))
  }

  async clear (): Promise<void> {
    localStorage.removeItem(this.key)
  }
}
