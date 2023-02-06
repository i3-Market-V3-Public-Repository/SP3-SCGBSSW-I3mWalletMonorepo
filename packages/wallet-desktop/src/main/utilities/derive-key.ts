import { KeyObject, createSecretKey } from 'crypto'
import pbkdf2Hmac from 'pbkdf2-hmac'

export interface PbkdfSettings {
  usage: string
  iterations: number
  keyLength: number
}

export const deriveKey = async (password: string | ArrayBuffer, salt: ArrayBuffer, settings: PbkdfSettings): Promise<KeyObject> => {
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
