import crypto from 'crypto'
import { v4 as uuidv4 } from 'uuid'

import base64Url from './base64url'

interface SecretJwk {
  kid: string
  kty: string
  k: string
}
const jwkSecret = (secret: Buffer = crypto.randomBytes(32)): SecretJwk => {
  const jwk: SecretJwk = {
    kid: uuidv4(),
    kty: 'oct',
    k: base64Url.encode(secret)
  }
  return jwk
}

export { jwkSecret }
export default jwkSecret
