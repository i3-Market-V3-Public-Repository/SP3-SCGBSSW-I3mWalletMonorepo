import { CodeGenerator, MasterKey } from '@i3-market/wallet-protocol'
import { EncryptJWT, jwtDecrypt, KeyLike } from 'jose'

export class JwtCodeGenerator implements CodeGenerator {
  constructor (protected key: KeyLike | Uint8Array) { }

  async generate (masterKey: MasterKey): Promise<Uint8Array> {
    const payload = masterKey.toJSON()
    const token = await new EncryptJWT(payload)
      .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
      .setAudience(masterKey.from.name)
      .setIssuer(masterKey.from.name)
      .setSubject(masterKey.to.name)
      .setExpirationTime('4 weeks')
      .encrypt(this.key)

    return Buffer.from(token, 'utf8')
  }

  async getMasterKey (code: Uint8Array): Promise<MasterKey> {
    const jwt = Buffer.from(code).toString('utf8')
    const { payload } = await jwtDecrypt(jwt, this.key)

    return await MasterKey.fromJSON(payload)
  }
}
