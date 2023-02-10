import axios, { AxiosRequestConfig } from 'axios'
import { VaultError } from './error'

interface Options {
  bearerToken?: string
  responseStatus?: number
}

async function get<T> (url: string, options?: Options): Promise<T> {
  const headers: AxiosRequestConfig['headers'] = {
    'Content-Type': 'application/json'
  }
  if (options?.bearerToken !== undefined) {
    headers.Authorization = 'Bearer ' + options.bearerToken
  }
  const res = await axios.get<T>(
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

async function delet<T> (url: string, options?: Options): Promise<T> {
  const headers: AxiosRequestConfig['headers'] = {
    'Content-Type': 'application/json'
  }
  if (options?.bearerToken !== undefined) {
    headers.Authorization = 'Bearer ' + options.bearerToken
  }
  const res = await axios.delete<T>(
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

async function post<T> (url: string, requestBody: any, options?: Options): Promise<T> {
  const headers: AxiosRequestConfig['headers'] = {
    'Content-Type': 'application/json'
  }
  if (options?.bearerToken !== undefined) {
    headers.Authorization = 'Bearer ' + options.bearerToken
  }
  const res = await axios.post<T>(
    url,
    requestBody,
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

async function put<T> (url: string, requestBody: any, options?: Options): Promise<T> {
  const headers: AxiosRequestConfig['headers'] = {
    'Content-Type': 'application/json'
  }
  if (options?.bearerToken !== undefined) {
    headers.Authorization = 'Bearer ' + options.bearerToken
  }
  const res = await axios.put<T>(
    url,
    requestBody,
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

export default {
  get,
  post,
  put,
  delete: delet
}
