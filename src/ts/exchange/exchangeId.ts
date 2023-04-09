import * as b64 from '@juanelas/base64'
import { hashable } from 'object-sha'
import { DataExchange } from '../types.js'
import { sha } from '../utils/index.js'

/**
 * Returns the exchangeId of the data exchange. The id is computed hashing an object with
 * all the properties of the data exchange but the id.
 *   id = BASE64URL(SHA256(hashable(dataExchangeButId)))
 * @param exchange - a complete data exchange without an id
 * @returns the exchange id in hexadecimal
 */
export async function exchangeId (exchange: Omit<DataExchange, 'id'>): Promise<string> {
  return b64.encode(await sha(hashable(exchange), 'SHA-256'), true, false)
}
