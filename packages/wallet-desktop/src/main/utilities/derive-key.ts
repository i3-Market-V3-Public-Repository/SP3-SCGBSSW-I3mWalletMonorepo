import crypto, { KeyObject, createSecretKey, createHash } from 'node:crypto'
import pbkdf2Hmac from 'pbkdf2-hmac'
// import { scrypt } from 'scrypt-pbkdf'

import { KeyDerivation, KeyDerivationContext, PbkdfAlgorithms } from '@wallet/lib'
import { logger } from '@wallet/main/internal'

export interface PbkdfSettings {
  usage: string
  iterations: number
  keyLength: number
}

export const deriveKeyOld = async (password: string | ArrayBuffer, salt: ArrayBuffer, settings: PbkdfSettings): Promise<KeyObject> => {
  let passwordBuffer: ArrayBuffer
  if (password instanceof ArrayBuffer) {
    passwordBuffer = password
  } else {
    passwordBuffer = Buffer.from(password)
  }
  const usageBuffer = Buffer.from(settings.usage)

  const p = new Uint8Array(passwordBuffer.byteLength + usageBuffer.byteLength)
  p.set(new Uint8Array(passwordBuffer), 0)
  p.set(new Uint8Array(usageBuffer), passwordBuffer.byteLength)

  const keyBuffer = await pbkdf2Hmac(
    p,
    salt,
    settings.iterations,
    settings.keyLength
  )
  return createSecretKey(Buffer.from(keyBuffer))
}

const parseKeyDerivationPattern = (p: string, kdCtx: KeyDerivationContext): Buffer | string => {
  const parsed = p.replace(/\{(\w+)\}/gm, (match, name: string) => {
    const value = kdCtx[name]
    if (value === undefined) {
      logger.warn(`Undefined key context value for context: '${name}'. Using UNKOWN as value...`)
      return 'UNKNOWN'
    } else if (value instanceof KeyObject) {
      return value.export().toString('base64')
    } else if (value instanceof Buffer) {
      return value.toString('base64')
    }
    return value
  })
  // try {
  //   return Buffer.from(parsed, 'base64')
  // } catch {
  //   return parsed
  // }

  return parsed
}

const parseSalt = (kd: KeyDerivation, kdCtx: KeyDerivationContext): Buffer => {
  const saltString = parseKeyDerivationPattern(kd.salt_pattern, kdCtx)
  const hash = createHash(kd.salt_hashing_algorithm)
  return hash.update(saltString).digest()
}

const derivePbkdf2 = async (password: string | Buffer, salt: Buffer, kd: KeyDerivation<'pbkdf2'>, kdCtx: KeyDerivationContext): Promise<KeyObject> => {
  const keyBuffer = await pbkdf2Hmac(
    password,
    salt,
    kd.alg_options.iterations,
    kd.derived_key_length
  )
  return createSecretKey(Buffer.from(keyBuffer))
}

const deriveScrypt = async (password: string | Buffer, salt: Buffer, kd: KeyDerivation<'scrypt'>, kdCtx: KeyDerivationContext): Promise<KeyObject> => {
  return await new Promise<KeyObject>(resolve => {
    crypto.scrypt(
      password,
      salt,
      kd.derived_key_length,
      {
        ...kd.alg_options,
        maxmem: 160 * kd.alg_options.N * kd.alg_options.r
      },
      (err, deriveKey) => {
        if (err !== undefined) {
          const key = createSecretKey(Buffer.from(deriveKey))
          resolve(key)
        }
      })
  })
  // const keyBuffer = scrypt(
  //   password,
  //   salt,
  //   kd.derived_key_length,
  //   kd.alg_options
  // )
}

const checkKeyDerivationType = <Alg extends PbkdfAlgorithms>(kd: KeyDerivation, alg: Alg): kd is KeyDerivation<Alg> => {
  return kd.alg === alg
}

export const deriveKey = async (kd: KeyDerivation, kdCtx: KeyDerivationContext): Promise<KeyObject> => {
  const password = parseKeyDerivationPattern(kd.input_pattern, kdCtx)
  const salt = parseSalt(kd, kdCtx)

  if (checkKeyDerivationType(kd, 'pbkdf2')) {
    return await derivePbkdf2(password, salt, kd, kdCtx)
  }
  if (checkKeyDerivationType(kd, 'scrypt')) {
    return await deriveScrypt(password, salt, kd, kdCtx)
  }

  throw new Error('Unknown pbkdf algorithm')
}
