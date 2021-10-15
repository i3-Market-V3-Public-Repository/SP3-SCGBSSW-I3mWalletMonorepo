
export interface WalletFunctionMetadata {
  name: string
  description?: string
  call: string
}

export interface WalletMetadata {
  name: string
  features: {
    [feature: string]: any
  }
  functions: WalletFunctionMetadata[]
}
