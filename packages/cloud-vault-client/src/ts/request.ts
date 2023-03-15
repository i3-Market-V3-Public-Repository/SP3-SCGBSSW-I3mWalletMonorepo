import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios'
import axiosRetry from 'axios-retry'
import { VaultError } from './error'

export interface RetryOptions {
  retries: number
  retryDelay: number // milliseconds
}

interface CallOptions {
  bearerToken?: string
  responseStatus?: number
  sequentialPost?: boolean // post/put to the same url will be handled sequentially
}

export class Request {
  axios: AxiosInstance
  defaultCallOptions?: CallOptions
  defaultUrl?: string
  private _stop: boolean
  uploading: {
    [url: string]: Array<Promise<AxiosResponse>>
  }

  constructor (opts?: {
    retryOptions?: RetryOptions
    defaultCallOptions?: CallOptions
    defaultUrl?: string
  }) {
    this._stop = false
    this.axios = this.getAxiosInstance(opts?.retryOptions)
    this.defaultCallOptions = opts?.defaultCallOptions
    this.defaultUrl = opts?.defaultUrl
    this.uploading = {}
  }

  private getAxiosInstance (retryOptions?: RetryOptions): AxiosInstance {
    const axiosInstance = axios.create()

    if (retryOptions?.retries !== undefined) {
      axiosRetry(axiosInstance, {
        retries: retryOptions.retries,
        retryDelay: () => {
          return retryOptions.retryDelay
        },
        retryCondition: () => {
          return this._stop
        }
      })
    }

    return axiosInstance
  }

  async waitForUploadsToFinsh (url?: string): Promise<void> {
    const url2 = (url !== undefined) ? url : this.defaultUrl
    if (url2 === undefined) {
      throw new VaultError('error', new Error('no url or defaultUrl provided'), { cause: 'you should create the Request object with a defaultUrl or pass the url oof the uploads you want to wait to finish' })
    }
    if (this.uploading[url2] !== undefined) {
      for (const promise of this.uploading[url2]) {
        try {
          await promise
        } catch (error) { }
      }
    }
  }

  async stop (): Promise<void> {
    this._stop = true
    for (const url in this.uploading) {
      await this.waitForUploadsToFinsh(url).catch()
    }
    this._stop = false
  }

  async get<T> (url: string, options?: CallOptions): Promise<T>
  async get<T> (options?: CallOptions): Promise<T>
  async get<T> (urlOrOptions?: string | CallOptions, opts?: CallOptions): Promise<T> {
    const url = (typeof urlOrOptions === 'string') ? urlOrOptions : this.defaultUrl
    if (url === undefined) {
      throw new VaultError('error', new Error('no url or defaultUrl provided'), { cause: 'you should create the Request object with a defaultUrl or pass the url to the HTTP method' })
    }
    const options = (typeof urlOrOptions !== 'string') ? urlOrOptions : opts
    const headers: AxiosRequestConfig['headers'] = {
      'Content-Type': 'application/json'
    }
    if (options?.bearerToken !== undefined) {
      headers.Authorization = 'Bearer ' + options.bearerToken
    }

    if (this._stop) {
      throw new VaultError('http-request-canceled', {
        request: {
          method: 'GET',
          url,
          headers: headers as { [header: string]: string }
        }
      })
    }

    const res = await this.axios.get<T>(
      url,
      {
        headers
      }).catch(error => {
      throw VaultError.from(error)
    })

    if (options?.responseStatus !== undefined && res.status !== options.responseStatus) {
      throw new VaultError('validation', {
        description: `Received HTTP status ${res.status} does not match the expected one (${options.responseStatus})`
      }, { cause: 'HTTP status does not match the expected one' })
    }
    return res.data
  }

  async delete<T> (url: string, options?: CallOptions): Promise<T>
  async delete<T> (options?: CallOptions): Promise<T>
  async delete<T> (urlOrOptions?: string | CallOptions, opts?: CallOptions): Promise<T> {
    const url = (typeof urlOrOptions === 'string') ? urlOrOptions : this.defaultUrl
    if (url === undefined) {
      throw new VaultError('error', new Error('no url or defaultUrl provided'), { cause: 'you should create the Request object with a defaultUrl or pass the url to the HTTP method' })
    }
    const options = (typeof urlOrOptions !== 'string') ? urlOrOptions : opts

    const headers: AxiosRequestConfig['headers'] = {
      'Content-Type': 'application/json'
    }
    if (options?.bearerToken !== undefined) {
      headers.Authorization = 'Bearer ' + options.bearerToken
    }
    if (this._stop) {
      throw new VaultError('http-request-canceled', {
        request: {
          method: 'DELETE',
          url,
          headers: headers as { [header: string]: string }
        }
      })
    }
    const res = await this.axios.delete<T>(
      url,
      {
        headers
      }).catch(error => { throw VaultError.from(error) })
    if (options?.responseStatus !== undefined && res.status !== options.responseStatus) {
      throw new VaultError('validation', {
        description: `Received HTTP status ${res.status} does not match the expected one (${options.responseStatus})`
      }, { cause: 'HTTP status does not match the expected one' })
    }
    return res.data
  }

  private async upload<T> (method: 'post' | 'put', url: string, requestBody: any, options?: CallOptions): Promise<T> {
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

    if (options?.sequentialPost === true) {
      await this.waitForUploadsToFinsh(url).catch()
    }
    this.uploading[url] = []

    const postPromise = this.axios[method]<T>(
      url,
      requestBody,
      {
        headers
      }
    )

    const index = this.uploading[url].push(postPromise) - 1
    const res = await postPromise.catch((err) => {
      throw VaultError.from(err)
    })

    if (index === this.uploading[url].length - 1) {
      this.uploading[url].pop() // eslint-disable-line @typescript-eslint/no-floating-promises
    } else {
      let i = index
      do {
        delete this.uploading[url][index] // eslint-disable-line @typescript-eslint/no-dynamic-delete
        i--
      } while (this.uploading[url][i] === undefined)
    }
    if (this.uploading[url].length === 0) {
      delete this.uploading[url] // eslint-disable-line @typescript-eslint/no-dynamic-delete
    }

    if (options?.responseStatus !== undefined && res.status !== options.responseStatus) {
      throw new VaultError('validation', {
        description: `Received HTTP status ${res.status} does not match the expected one (${options.responseStatus})`
      }, { cause: 'HTTP status does not match the expected one' })
    }
    return res.data
  }

  async post<T> (url: string, requestBody: any, options?: CallOptions): Promise<T>
  async post<T> (requestBody: any, options?: CallOptions): Promise<T>
  async post<T> (urlOrRequestBody: string | any, requestBodyOrOptions: any | CallOptions, opts?: CallOptions): Promise<T> {
    let url, requestBody, options
    if (typeof urlOrRequestBody === 'string') {
      url = urlOrRequestBody
      requestBody = requestBodyOrOptions
      options = opts
    } else {
      url = this.defaultUrl
      requestBody = urlOrRequestBody
      options = requestBodyOrOptions
    }
    if (url === undefined) {
      throw new VaultError('error', new Error('no url or defaultUrl provided'), { cause: 'you should create the Request object with a defaultUrl or pass the url to the HTTP method' })
    }
    return await this.upload('post', url, requestBody, options)
  }

  async put<T> (url: string, requestBody: any, options?: CallOptions): Promise<T>
  async put<T> (requestBody: any, options?: CallOptions): Promise<T>
  async put<T> (urlOrRequestBody: string | any, requestBodyOrOptions: any | CallOptions, opts?: CallOptions): Promise<T> {
    let url, requestBody, options
    if (typeof urlOrRequestBody === 'string') {
      url = urlOrRequestBody
      requestBody = requestBodyOrOptions
      options = opts
    } else {
      url = this.defaultUrl
      requestBody = urlOrRequestBody
      options = requestBodyOrOptions
    }
    if (url === undefined) {
      throw new VaultError('error', new Error('no url or defaultUrl provided'), { cause: 'you should create the Request object with a defaultUrl or pass the url to the HTTP method' })
    }
    return await this.upload('put', url, requestBody, options)
  }
}
