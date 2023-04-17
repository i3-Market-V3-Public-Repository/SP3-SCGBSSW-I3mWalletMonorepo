
export class WalletApiError extends Error {
  constructor (message: string, public code: number, public body: any) {
    super(message)
  }
}
