import { OpenApiComponents } from '@i3m/cloud-vault-server/types/openapi'
import { AxiosError } from 'axios'

export type VaultErrorData = { // eslint-disable-line @typescript-eslint/consistent-type-definitions
  'not-initialized': any
  'http-connection-error': {
    request: {
      method?: string
      url?: string
      headers?: { [header: string]: string }
      data?: any
    }
    response?: {
      status?: number
      headers?: { [header: string]: string }
      data?: any
    }
  }
  'no-uploadded-storage': any
  'sse-connection-error': Event
  conflict: {
    localTimestamp?: number // timestamp in milliseconds elapsed from EPOCH when the latest storage has been downloaded by this client
    remoteTimestamp?: number // timestamp in milliseconds elapsed from EPOCH when the latest storage has been uploaded by any client
  }
  unauthorized: any
  error: any
  unknown: any
  validation: {
    description?: string
    data?: any
  }
}
type VaultErrorName = keyof VaultErrorData
type DataForError<T extends VaultErrorName> = VaultErrorData[T]

export class VaultError<T extends VaultErrorName = VaultErrorName> extends Error {
  data: any
  message: T

  constructor (message: T, data: DataForError<T>, options?: ErrorOptions)
  constructor (message: string, data?: any, options?: ErrorOptions) {
    super(message, options)
    this.name = 'VaultError'
    this.data = data
    this.message = message as T
  }

  static from (error: unknown): VaultError {
    if (error instanceof VaultError) return error
    if (error instanceof Event) { // SSE problem
      return new VaultError('sse-connection-error', error, { cause: 'Likely issues connecting to the events endpoint of the cloud vault server' })
    }
    if (error instanceof AxiosError) {
      if ((error.response?.data as OpenApiComponents.Schemas.ApiError).name === 'Unauthorized') {
        return new VaultError('unauthorized', undefined)
      }
      if (error.response?.status === 404 && error.response.data.name === 'no storage') {
        return new VaultError('no-uploadded-storage', undefined)
      }
      const vaultConnError: VaultErrorData['http-connection-error'] = {
        request: {
          method: error.config?.method?.toLocaleUpperCase(),
          url: error.config?.url,
          headers: error.config?.headers,
          data: error.config?.data
        },
        response: {
          status: error.response?.status,
          headers: error.response?.headers as { [key: string]: string },
          data: error.response?.data
        }
      }
      return new VaultError('http-connection-error', vaultConnError)
    }
    if (error instanceof Error) {
      const vaultError = new VaultError('error', error, { cause: error.cause })
      vaultError.stack = error.stack
      return vaultError
    }
    return new VaultError('unknown', error)
  }
}
