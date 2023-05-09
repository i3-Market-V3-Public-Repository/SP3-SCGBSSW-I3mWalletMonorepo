import { CodeGenerator, MasterKey } from '@i3m/wallet-protocol'
import { EncryptJWT, jwtDecrypt, KeyLike } from 'jose'

import { Locals } from '@wallet/main/internal'
import { DEFAULT_TOKEN_TLL } from '@wallet/lib'

export class JwtCodeGenerator implements CodeGenerator {
  constructor (protected key: KeyLike | Uint8Array, protected locals: Locals) { }

  async generate (masterKey: MasterKey): Promise<Uint8Array> {
    const { sharedMemoryManager: shm } = this.locals
    const payload = masterKey.toJSON()
    const iat = Math.trunc(new Date().getTime() / 1000)
    const token = new EncryptJWT(payload)
      .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
      .setAudience(masterKey.from.name)
      .setIssuer(masterKey.from.name)
      .setSubject(masterKey.to.name)
      .setIssuedAt(iat)

    const connect = shm.memory.settings.private.connect
    if (connect.enableTokenExpiration) {
      const exp = iat + (connect.tokenTTL ?? DEFAULT_TOKEN_TLL)
      token.setExpirationTime(exp)
    }

    const data = await token.encrypt(this.key)

    return Buffer.from(data, 'utf8')
  }

  async getMasterKey (code: Uint8Array): Promise<MasterKey> {
    const jwt = Buffer.from(code).toString('utf8')
    const { payload } = await jwtDecrypt(jwt, this.key)

    return await MasterKey.fromJSON(payload)
  }
}
