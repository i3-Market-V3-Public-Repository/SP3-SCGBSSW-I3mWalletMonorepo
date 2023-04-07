import { parseProccessEnvVar } from './parseProcessEnvVar.js'
import { randomBytes } from 'node:crypto'

const secret = parseProccessEnvVar('JWT_SECRET', 'string', { defaultValue: randomBytes(32).toString('hex') })
const alg = parseProccessEnvVar('JWT_ALG', 'string', { defaultValue: 'HS512', allowedValues: ['HS256', 'HS384', 'HS512'] }) as 'HS256' | 'HS384' | 'HS512'
const expiresIn = Number(parseProccessEnvVar('JWT_EXPIRES_IN', 'string', { defaultValue: '7862400' }))

export const jwt = {
  alg,
  secret,
  expiresIn
}
