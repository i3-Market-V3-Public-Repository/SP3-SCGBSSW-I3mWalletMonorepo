import type { OpenApiComponents } from '@i3m/cloud-vault-server/types/openapi'
import { createCipheriv, createDecipheriv, KeyObject, randomBytes } from 'crypto'

export class SecretKey {
  private readonly key: KeyObject
  readonly alg: OpenApiComponents.Schemas.VaultConfiguration['key_derivation']['enc']['enc_algorithm']

  constructor (key: KeyObject, alg: OpenApiComponents.Schemas.VaultConfiguration['key_derivation']['enc']['enc_algorithm']) {
    this.key = key
    this.alg = alg
  }

  encrypt (input: Buffer): Buffer {
    // random initialization vector
    const iv = randomBytes(16)

    // Create the cipher
    const cipher = createCipheriv(this.alg, this.key, iv)

    // encrypt the given text
    const encrypted = Buffer.concat([cipher.update(input), cipher.final()])

    // extract the auth tag
    const tag = cipher.getAuthTag()

    // generate output
    return Buffer.concat([iv, tag, encrypted])
  }

  decrypt (input: Buffer): Buffer {
    // extract all parts
    const iv = input.subarray(0, 16)
    const tag = input.subarray(16, 32)
    const ciphertext = input.subarray(32)

    // Create the decipher
    const decipher = createDecipheriv(this.alg, this.key, iv)
    decipher.setAuthTag(tag)

    // decrypt
    return Buffer.concat([decipher.update(ciphertext), decipher.final()])
  }
}
