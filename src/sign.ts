import CompactSign from 'jose/jws/compact/sign'
import parseJwk from 'jose/jwk/parse'

export async function sign (a: string): Promise<string> {
  const encoder = new TextEncoder()
  const privateKey = await parseJwk({
    alg: 'ES256',
    crv: 'P-256',
    kty: 'EC',
    d: 'VhsfgSRKcvHCGpLyygMbO_YpXc7bVKwi12KQTE4yOR4',
    x: 'ySK38C1jBdLwDsNWKzzBHqKYEE5Cgv-qjWvorUXk9fw',
    y: '_LeQBw07cf5t57Iavn4j-BqJsAD1dpoz8gokd3sBsOo'
  })

  const jws = await new CompactSign(encoder.encode(JSON.stringify({ msg: 'It’s a dangerous business, Frodo, going out your door.' })))
    .setProtectedHeader({ alg: 'ES256' })
    .sign(privateKey)

  console.log(jws)
  return jws
}
