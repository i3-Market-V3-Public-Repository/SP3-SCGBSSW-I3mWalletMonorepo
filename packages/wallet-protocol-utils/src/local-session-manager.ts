import { WalletProtocol, Session, Transport } from '@i3-market/wallet-protocol'
import { BehaviorSubject, Subject } from 'rxjs'

export interface SessionManagerOptions {
  localStorageKey: string
}

export class LocalSessionManager<T extends Transport = Transport> {
  protected opts: SessionManagerOptions
  public session: Session<T> | undefined
  public $session: Subject<Session<T> | undefined>

  constructor (protected protocol: WalletProtocol<T>, options: Partial<SessionManagerOptions> = {}) {
    this.opts = {
      localStorageKey: options.localStorageKey ?? 'wallet-session'
    }
    this.$session = new BehaviorSubject<Session<T> | undefined>(undefined)
  }

  get hasSession (): boolean {
    return this.session !== undefined
  }


  fetch = new Proxy(fetch, {
    apply: (oldFecth, thisArg, argArray) => {
      if (!this.session) {
        throw new Error('no session')
      }

      return this.session.send({
        url: argArray[0],
        init: argArray[1]
      } as any)
    }
  })

  async createIfNotExists (): Promise<Session<T>> {
    if (this.session !== undefined) {
      return this.session
    }
    const session = await this.protocol.run()
    this.setSession(session)

    return session
  }

  removeSession(): void {
    this.setSession()
  }

  setSession (session?: Session<T>): void {
    this.session = session
    if (session === undefined) {
      localStorage.removeItem('wallet-session')
    } else {
      const sessionJson = session.toJSON()
      localStorage.setItem('wallet-session', JSON.stringify(sessionJson))
    }
    this.$session.next(session)
  }

  async loadSession (): Promise<void> {
    let session: Session<T> | undefined
    const sessionJson = localStorage.getItem('wallet-session')
    if (sessionJson !== null) {
      session = await Session.fromJSON(this.protocol.transport, JSON.parse(sessionJson))  
    }
    this.setSession(session)
  }
}
