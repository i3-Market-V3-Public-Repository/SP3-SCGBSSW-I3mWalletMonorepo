import base64url from './base64url'

/**
 * Prepares header and payload, received as standard JS objects, to be signed as needed for a JWS/JWT signature.
 *
 * @param header
 * @param payload
 * @param encoding
 * @returns <base64url(header)>.<base64url(payload)>
 */
export function jwsSignInput (header: object, payload: object, encoding?: BufferEncoding): string {
  var encodedHeader = base64url.encode(Buffer.from(JSON.stringify(header), 'binary'))
  var encodedPayload = base64url.encode(Buffer.from(JSON.stringify(payload), encoding))

  return `${encodedHeader}.${encodedPayload}`
}
