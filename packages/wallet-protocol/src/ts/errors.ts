
export class WalletProtocolError extends Error {
  constructor(message: string, public readonly httpCode: number = 500, readonly parentError?: unknown) {
    super(message)
  }
}

export class InvalidPinError extends WalletProtocolError {

}
