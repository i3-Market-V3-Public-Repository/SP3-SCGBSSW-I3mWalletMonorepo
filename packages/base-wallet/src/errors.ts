
interface HttpData {
  code?: number
  status?: number
}

export class WalletError extends Error {
  public code: number
  public status: number

  constructor (message: string, httpData?: HttpData) {
    super(message)
    this.code = httpData?.code ?? 1
    this.status = httpData?.status ?? 500
  }
}
