
export class Subject<T=unknown> {
  protected resolve?: (value: T) => void
  protected reject?: (reason: any) => void

  get promise (): Promise<T> {
    return this.createPromise()
  }

  protected async createPromise (): Promise<T> {
    return await new Promise<T>((resolve, reject) => {
      this.resolve = resolve
      this.reject = reject
    })
  }

  next (value: T): void {
    if (this.resolve != null) {
      this.resolve(value)
    }
  }

  err (reason: any): void {
    if (this.reject != null) {
      this.reject(reason)
    }
  }
}
