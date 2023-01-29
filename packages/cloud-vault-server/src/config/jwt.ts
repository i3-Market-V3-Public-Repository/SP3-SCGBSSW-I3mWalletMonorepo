import { parseProccessEnvVar } from './parseProcessEnvVar'
import { randomBytes } from 'crypto'
import { Algorithm } from 'jsonwebtoken'

const secret = parseProccessEnvVar('JWT_SECRET', { defaultValue: randomBytes(32).toString('hex') }) as 'string'

export const jwt = {
  alg: 'HS512' as Algorithm,
  secret
}
