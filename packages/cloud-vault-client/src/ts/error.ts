import { OpenApiComponents } from '@i3m/cloud-vault-server/types/openapi'
import { AxiosError } from 'axios'
import { } from 'eventsource'

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
  'no-uploaded-storage': any
  'sse-connection-error': any
  'quota-exceeded': string
  conflict: {
    localTimestamp?: number // timestamp in milliseconds elapsed from EPOCH when the latest storage has been downloaded by this client
    remoteTimestamp?: number // timestamp in milliseconds elapsed from EPOCH when the latest storage has been uploaded by any client
  }
  unauthorized: any
  'invalid-credentials': any
  error: Error // unknown error generated as an instance of Error
  unknown: any // unknown error not as an instance of Error
  validation: {
    description?: string
    data?: any
  }
}
export type VaultErrorName = keyof VaultErrorData
export type DataForError<T extends VaultErrorName> = VaultErrorData[T]

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
    if (error instanceof Object && error.constructor.name === 'Event') { // SSE problem
      return new VaultError('sse-connection-error', error, { cause: 'Likely issues connecting to the events endpoint of the cloud vault server' })
    }
    if (error instanceof AxiosError) {
      const err = error.response?.data as OpenApiComponents.Schemas.ApiError | OpenApiComponents.Schemas.ErrorUnauthorized | OpenApiComponents.Schemas.ErrorAlreadyRegistered | OpenApiComponents.Schemas.ErrorInvalidCredentials | OpenApiComponents.Schemas.ErrorNoStorage | OpenApiComponents.Schemas.ErrorNotRegistered | OpenApiComponents.Schemas.ErrorQuotaExceeded | OpenApiComponents.Schemas.ErrorUnauthorized
      switch (err.name) {
        case 'no-storage':
          return new VaultError('no-uploaded-storage', undefined)
        case 'invalid-credentials':
          return new VaultError('invalid-credentials', undefined)
        case 'quota-exceeded':
          return new VaultError('quota-exceeded', err.description)
        case 'unauthorized':
        case 'not-registered':
          return new VaultError('unauthorized', undefined)
        default:
          break
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

export function checkErrorType <T extends VaultErrorName> (err: VaultError, type: T): err is VaultError<T> {
  return err.message === type
}
