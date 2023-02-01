export class QuerablePromise<T> {
  isPending: boolean
  isRejected: boolean
  isFulfilled: boolean
  then: <TResult1 = T, TResult2 = never>(onfulfilled?: ((value: T) => TResult1 | PromiseLike<TResult1>) | null | undefined, onrejected?: ((reason: any) => TResult2 | PromiseLike<TResult2>) | null | undefined) => Promise<TResult1 | TResult2>
  catch: <TResult = never>(onrejected?: ((reason: any) => TResult | PromiseLike<TResult>) | null | undefined) => Promise<T | TResult>
  finally: (onfinally?: (() => void) | null | undefined) => Promise<T>

  constructor (promise: Promise<T>) {
    this.isPending = true
    this.isRejected = false
    this.isFulfilled = false
    this.then = promise.then
    this.catch = promise.catch
    this.finally = promise.finally

    promise.then(
      (v: any) => {
        this.isFulfilled = true
        this.isPending = false
        return v
      },
      (e: any) => {
        this.isRejected = true
        this.isPending = false
        throw e
      }
    )
  }
}
