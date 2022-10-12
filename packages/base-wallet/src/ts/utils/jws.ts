import base64url from './base64url'

export interface DecodedJWS {
  header: any
  payload: any
  signature: string
  data: string
}

/**
 * Prepares header and payload, received as standard JS objects, to be signed as needed for a JWS/JWT signature.
 *
 * @param header
 * @param payload
 * @param encoding
 * @returns <base64url(header)>.<base64url(payload)>
 */
export function jwsSignInput (header: object, payload: object, encoding?: BufferEncoding): string {
  const encodedHeader = base64url.encode(Buffer.from(JSON.stringify(header), 'binary'))
  const encodedPayload = base64url.encode(Buffer.from(JSON.stringify(payload), encoding))

  return `${encodedHeader}.${encodedPayload}`
}

/**
 * Returns a decoded JWS
 *
 * @param jws
 * @param encoding
 * @returns
 */
export function decodeJWS (jws: string, encoding?: BufferEncoding): DecodedJWS {
  const parts = jws.match(/^([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
  if (parts != null) {
    return {
      header: JSON.parse(base64url.decode(parts[1]).toString('binary')),
      payload: JSON.parse(base64url.decode(parts[2]).toString(encoding)),
      signature: parts[3],
      data: `${parts[1]}.${parts[2]}`
    }
  }
  throw new Error('invalid_argument: Incorrect format JWS')
}
