import { WalletProtocolError } from '../internal'
import { Queue } from './queue'

type Resolver<T> = (value: T) => void
type Rejecter = (reason: any) => void

export class Subject<T=unknown> {
  protected queue: Queue<T>
  protected resolvePending?: Resolver<T>
  protected rejectPending?: Rejecter

  constructor (public readonly queueLength = 1) {
    this.queue = new Queue(queueLength)
  }

  get promise (): Promise<T> {
    return this.createPromise()
  }

  protected async createPromise (): Promise<T> {
    const v = this.queue.pop()
    if (v !== undefined) {
      return v
    }

    return await new Promise<T>((resolve, reject) => {
      if (this.rejectPending !== undefined || this.resolvePending !== undefined) {
        reject(new WalletProtocolError('wallet protocol: cannot create two promises of one subject'))
        this.unbindPromise()
        return
      }

      this.resolvePending = (v) => {
        resolve(v)
      }
      this.rejectPending = (err) => reject(err)
    })
  }

  next (value: T): void {
    if (this.resolvePending != null) {
      this.resolvePending(value)
      this.unbindPromise()
    } else {
      this.queue.push(value)
    }
  }

  err (reason: any): void {
    if (this.rejectPending != null) {
      this.rejectPending(reason)
      this.unbindPromise()
    }
  }

  finish (): void {
    if (this.rejectPending !== undefined) {
      this.rejectPending(new WalletProtocolError('wallet protocol: the subject has a pending promise'))
      this.unbindPromise()
    }
  }

  private unbindPromise (): void {
    this.resolvePending = undefined
    this.rejectPending = undefined
  }
}
