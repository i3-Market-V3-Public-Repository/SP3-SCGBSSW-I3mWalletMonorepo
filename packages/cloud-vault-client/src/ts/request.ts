import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios'
import axiosRetry, { isNetworkOrIdempotentRequestError } from 'axios-retry'
import { VaultError } from './error'

export interface RetryOptions {
  retries: number
  retryDelay: number // milliseconds
}

interface CallOptions<T = unknown> {
  bearerToken?: string
  responseStatus?: number
  sequential?: boolean // request will be performed sequentially
  beforeRequestFinish?: (data: T) => Promise<void>
}

export class Request {
  private readonly axios: AxiosInstance
  _defaultCallOptions: CallOptions
  _defaultUrl?: string
  private _stop: boolean
  ongoingRequests: {
    [url: string]: Array<Promise<AxiosResponse>>
  }

  constructor (opts?: {
    retryOptions?: RetryOptions
    defaultCallOptions?: CallOptions
    defaultUrl?: string
  }) {
    this._stop = false
    this.axios = this.getAxiosInstance(opts?.retryOptions)
    this._defaultCallOptions = opts?.defaultCallOptions ?? {}
    this._defaultUrl = opts?.defaultUrl
    this.ongoingRequests = {}
  }

  get defaultUrl (): string | undefined {
    return this.defaultUrl
  }

  set defaultUrl (url: string | undefined) {
    this._defaultUrl = url
  }

  get defaultCallOptions (): CallOptions {
    return this._defaultCallOptions
  }

  set defaultCallOptions (opts: CallOptions) {
    this._defaultCallOptions = {
      ...this._defaultCallOptions,
      ...opts
    }
  }

  private getAxiosInstance (retryOptions?: RetryOptions): AxiosInstance {
    const axiosInstance = axios.create()

    if (retryOptions?.retries !== undefined) {
      axiosRetry(axiosInstance, {
        retries: retryOptions.retries,
        retryDelay: () => {
          return retryOptions.retryDelay
        },
        retryCondition: (err) => {
          const cond1 = isNetworkOrIdempotentRequestError(err)
          const cond2 = !this._stop
          return cond2 && cond1
        }
      })
    }

    return axiosInstance
  }

  async waitForOngoingRequestsToFinsh (url?: string): Promise<void> {
    const url2 = (url !== undefined) ? url : this._defaultUrl
    if (url2 === undefined) {
      throw new VaultError('error', new Error('no url or defaultUrl provided'), { cause: 'you should create the Request object with a defaultUrl or pass the url oof the uploads you want to wait to finish' })
    }
    if (this.ongoingRequests[url2] !== undefined) {
      for (const promise of this.ongoingRequests[url2]) {
        try {
          await promise
        } catch (error) { }
      }
    }
  }

  async stop (): Promise<void> {
    this._stop = true
    for (const url in this.ongoingRequests) {
      await this.waitForOngoingRequestsToFinsh(url).catch()
    }
    this._stop = false
  }

  private async request<T> (method: 'delete' | 'get' | 'post' | 'put', url: string, requestBody?: any, options?: CallOptions<T>): Promise<T> {
    const headers: AxiosRequestConfig['headers'] = {
      'Content-Type': 'application/json'
    }
    if (options?.bearerToken !== undefined) {
      headers.Authorization = 'Bearer ' + options.bearerToken
    }
    if (this._stop) {
      throw new VaultError('http-request-canceled', {
        request: {
          method: method.toUpperCase(),
          url,
          headers: headers as { [header: string]: string },
          data: requestBody
        }
      })
    }

    if (options?.sequential === true) {
      await this.waitForOngoingRequestsToFinsh(url).catch()
    }
    this.ongoingRequests[url] = []

    const requestPromise = (method === 'post' || method === 'put')
      ? this.axios[method]<T>(
        url,
        requestBody,
        {
          headers
        }
      )
      : this.axios[method]<T>(
        url,
        {
          headers
        }
      )

    const index = this.ongoingRequests[url].push(requestPromise) - 1

    const res = await requestPromise
      .catch((axiosError) => {
        delete this.ongoingRequests[url][index] // eslint-disable-line @typescript-eslint/no-dynamic-delete
        throw VaultError.from(axiosError)
      })

    const beforeRequestFinishes = options?.beforeRequestFinish
    if (beforeRequestFinishes !== undefined) {
      await beforeRequestFinishes(res.data)
    }

    delete this.ongoingRequests[url][index] // eslint-disable-line @typescript-eslint/no-dynamic-delete

    if (options?.responseStatus !== undefined && res.status !== options.responseStatus) {
      throw new VaultError('validation', {
        description: `Received HTTP status ${res.status} does not match the expected one (${options.responseStatus})`
      }, { cause: 'HTTP status does not match the expected one' })
    }
    return res.data
  }

  async delete<T> (url: string, options?: CallOptions<T>): Promise<T>
  async delete<T> (options?: CallOptions<T>): Promise<T>
  async delete<T> (urlOrOptions?: string | CallOptions, opts?: CallOptions<T>): Promise<T> {
    const url = (typeof urlOrOptions === 'string') ? urlOrOptions : this._defaultUrl
    if (url === undefined) {
      throw new VaultError('error', new Error('no url or defaultUrl provided'), { cause: 'you should create the Request object with a defaultUrl or pass the url to the HTTP method' })
    }
    const options = (typeof urlOrOptions !== 'string') ? urlOrOptions : opts

    return await this.request('delete', url, undefined, options)
  }

  async get<T> (url: string, options?: CallOptions<T>): Promise<T>
  async get<T> (options?: CallOptions<T>): Promise<T>
  async get<T> (urlOrOptions?: string | CallOptions<T>, opts?: CallOptions<T>): Promise<T> {
    const url = (typeof urlOrOptions === 'string') ? urlOrOptions : this._defaultUrl
    if (url === undefined) {
      throw new VaultError('error', new Error('no url or defaultUrl provided'), { cause: 'you should create the Request object with a defaultUrl or pass the url to the HTTP method' })
    }
    const options = (typeof urlOrOptions !== 'string') ? urlOrOptions : opts

    return await this.request('get', url, undefined, options)
  }

  async post<T> (url: string, requestBody: any, options?: CallOptions<T>): Promise<T>
  async post<T> (requestBody: any, options?: CallOptions<T>): Promise<T>
  async post<T> (urlOrRequestBody: string | any, requestBodyOrOptions: any | CallOptions<T>, opts?: CallOptions): Promise<T> {
    let url, requestBody, options
    if (typeof urlOrRequestBody === 'string') {
      url = urlOrRequestBody
      requestBody = requestBodyOrOptions
      options = opts
    } else {
      url = this._defaultUrl
      requestBody = urlOrRequestBody
      options = requestBodyOrOptions
    }
    if (url === undefined) {
      throw new VaultError('error', new Error('no url or defaultUrl provided'), { cause: 'you should create the Request object with a defaultUrl or pass the url to the HTTP method' })
    }
    return await this.request('post', url, requestBody, options)
  }

  async put<T> (url: string, requestBody: any, options?: CallOptions<T>): Promise<T>
  async put<T> (requestBody: any, options?: CallOptions<T>): Promise<T>
  async put<T> (urlOrRequestBody: string | any, requestBodyOrOptions: any | CallOptions<T>, opts?: CallOptions): Promise<T> {
    let url, requestBody, options
    if (typeof urlOrRequestBody === 'string') {
      url = urlOrRequestBody
      requestBody = requestBodyOrOptions
      options = opts
    } else {
      url = this._defaultUrl
      requestBody = urlOrRequestBody
      options = requestBodyOrOptions
    }
    if (url === undefined) {
      throw new VaultError('error', new Error('no url or defaultUrl provided'), { cause: 'you should create the Request object with a defaultUrl or pass the url to the HTTP method' })
    }
    return await this.request('put', url, requestBody, options)
  }
}
