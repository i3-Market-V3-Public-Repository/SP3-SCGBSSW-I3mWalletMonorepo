import { Session, Transport, WalletProtocol } from '@i3m/wallet-protocol'
import { BehaviorSubject, Subject } from 'rxjs'
import { SessionStorage, SessionStorageOptions, SessionManagerOpts, SessionManagerOptions } from './types'

/**
 * A session manager is used to create, remove, set and load wallet-protocol sessions created after sucessful pairing with a i3M-Wallet app.
 */
export class SessionManager<T extends Transport = Transport> {
  public session: Session<T> | undefined
  public $session: Subject<Session<T> | undefined>
  public initialized: Promise<void>
  protected storage!: SessionStorage
  protected protocol: WalletProtocol<T>

  constructor (options: SessionManagerOpts<T>) {
    this.protocol = options.protocol
    this.$session = new BehaviorSubject<Session<T> | undefined>(undefined)
    this.initialized = this.init()
  }

  private async init (storage?: SessionStorage, storageOptions?: SessionStorageOptions): Promise<void> {
    if (storage === undefined) {
      if (IS_BROWSER) {
        const SessionLocalStorage = (await import('./session-storages/session-localstorage')).SessionLocalStorage
        this.storage = new SessionLocalStorage(storageOptions?.localStorage)
      } else {
        const SessionFileStorage = (await import('./session-storages/session-file-storage')).SessionFileStorage
        this.storage = new SessionFileStorage(storageOptions?.fileStorage)
      }
    } else {
      this.storage = storage
    }
  }

  get hasSession (): boolean {
    return this.session !== undefined
  }

  fetch: Session<T>['send'] = async (...args) => {
    await this.initialized

    if (this.session == null) {
      throw new Error('no session')
    }

    return await this.session.send(...args)
  }

  async createIfNotExists (): Promise<Session<T>> {
    await this.initialized

    if (this.session !== undefined) {
      return this.session
    }
    const session = await this.protocol.run()
    await this.setSession(session)

    return session
  }

  async removeSession (): Promise<void> {
    await this.initialized

    await this.setSession()
  }

  async setSession (session?: Session<T>): Promise<void> {
    await this.initialized

    this.session = session
    if (session === undefined || session === null) {
      await this.storage.clear()
    } else {
      const sessionJson = session.toJSON()
      await this.storage.setSessionData(sessionJson)
    }
    this.$session.next(session)
  }

  async loadSession (): Promise<void> {
    await this.initialized

    let session: Session<T> | undefined
    try {
      const sessionJson = await this.storage.getSessionData()
      if (sessionJson !== null) {
        session = await Session.fromJSON(this.protocol.transport, sessionJson)
      }
    } catch (error) {}

    await this.setSession(session)
  }
}

/**
 * A session manager that uses the browser's Local Storage to store the wallet-protocol's session created after pairing with an i3M-Wallet app.
 *
 * @deprecated Use {@link SessionManager} instead. It will be removed in next major version update
 */
export class LocalSessionManager<T extends Transport = Transport> extends SessionManager<T> {
  constructor (protected protocol: WalletProtocol<T>, options: Partial<SessionManagerOptions> = {}) {
    super({ protocol, storageOptions: { localStorage: { key: options.localStorageKey } } })
  }
}
