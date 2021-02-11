import CompactSign from 'jose/jws/compact/sign'
import parseJwk from 'jose/jwk/parse'

/**
 * Signs input and returns compact JWS
 *
 * @param a - the input to sign
 *
 * @returns a promise that resolves to a compact JWS
 *
 */
export async function sign (a: ArrayBufferLike | string): Promise<string> {
  const privateKey = await parseJwk({
    alg: 'ES256',
    crv: 'P-256',
    kty: 'EC',
    d: 'VhsfgSRKcvHCGpLyygMbO_YpXc7bVKwi12KQTE4yOR4',
    x: 'ySK38C1jBdLwDsNWKzzBHqKYEE5Cgv-qjWvorUXk9fw',
    y: '_LeQBw07cf5t57Iavn4j-BqJsAD1dpoz8gokd3sBsOo'
  })
  const input = (typeof a === 'string') ? (new TextEncoder()).encode(a) : new Uint8Array(a)

  const jws = await new CompactSign(input)
    .setProtectedHeader({ alg: 'ES256' })
    .sign(privateKey)

  console.log(jws)
  return jws
}
