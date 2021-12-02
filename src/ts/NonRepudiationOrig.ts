import { JWK, JWTVerifyResult } from 'jose'
import { jweEncrypt } from './jwe'
import { HASH_ALG } from './constants'
import { createProof } from './createProof'
import { oneTimeSecret } from './oneTimeSecret'
import { DataExchange, DataExchangeInit, JwkPair, PoOPayload, PoPPayload, PoRPayload } from './types'
import { sha } from './sha'
import { verifyKeyPair } from './verifyKeyPair'
import { verifyProof } from './verifyProof'

interface Block {
  raw: Uint8Array
  jwe?: string
  secret?: JWK
  poo?: string
  por?: string
  pop?: string
}

export class NonRepudiationOrig {
  dataExchange: DataExchangeInit
  jwkPairOrig: JwkPair
  publicJwkDest: JWK
  block: Block
  checked: boolean

  constructor (dataExchangeId: DataExchange['id'], jwkPairOrig: JwkPair, publicJwkDest: JWK, block: Uint8Array, alg?: string) {
    this.jwkPairOrig = jwkPairOrig
    this.publicJwkDest = publicJwkDest
    if (alg !== undefined) {
      this.jwkPairOrig.privateJwk.alg = alg
      this.jwkPairOrig.publicJwk.alg = alg
      this.publicJwkDest.alg = alg
    } else if (this.jwkPairOrig.privateJwk.alg === undefined || this.jwkPairOrig.publicJwk.alg === undefined || this.publicJwkDest.alg === undefined) {
      throw new TypeError('"alg" argument is required when "jwk.alg" is not present')
    }

    this.dataExchange = {
      id: dataExchangeId,
      orig: JSON.stringify(this.jwkPairOrig.publicJwk),
      dest: JSON.stringify(this.publicJwkDest),
      hashAlg: HASH_ALG
    }
    this.block = {
      raw: block
    }
    this.checked = false
  }

  async init (): Promise<void> {
    await verifyKeyPair(this.jwkPairOrig.publicJwk, this.jwkPairOrig.privateJwk)

    this.block.secret = await oneTimeSecret()
    const secretStr = JSON.stringify(this.block.secret)
    this.block.jwe = await jweEncrypt(this.dataExchange.id, this.block.raw, this.block.secret)

    this.dataExchange = {
      ...this.dataExchange,
      cipherblockDgst: await sha(this.block.jwe, this.dataExchange.hashAlg),
      blockCommitment: await sha(this.block.raw, this.dataExchange.hashAlg),
      secretCommitment: await sha(secretStr, this.dataExchange.hashAlg)
    }

    this.checked = true
  }

  /**
   * Creates the proof of origin (PoO) as a compact JWS for the block of data. Besides returning its value, it is also stored in this.block.poo
   *
   */
  async generatePoO (): Promise<string> {
    this._checkInit()

    const payload: PoOPayload = {
      proofType: 'PoO',
      iss: 'orig',
      dataExchange: this.dataExchange
    }
    this.block.poo = await createProof(payload, this.jwkPairOrig.privateJwk)
    return this.block.poo
  }

  async verifyPoR (por: string): Promise<JWTVerifyResult> {
    this._checkInit()

    if (this.block?.poo === undefined) {
      throw new Error('Cannot verify a PoR if not even a PoO have been created')
    }

    const expectedPayloadClaims: PoRPayload = {
      proofType: 'PoR',
      iss: 'dest',
      dataExchange: this.dataExchange,
      pooDgst: await sha(this.block.poo, this.dataExchange.hashAlg)
    }
    const verified = await verifyProof(por, this.publicJwkDest, expectedPayloadClaims)
    this.block.por = por

    return verified
  }

  async generatePoP (verificationCode: string): Promise<string> {
    this._checkInit()

    if (this.block?.por === undefined) {
      throw new Error('Before computing a PoP, you have first to receive a verify a PoR')
    }

    const payload: PoPPayload = {
      proofType: 'PoP',
      iss: 'orig',
      dataExchange: this.dataExchange,
      porDgst: await sha(this.block.por, this.dataExchange.hashAlg),
      secret: JSON.stringify(this.block.secret),
      verificationCode: verificationCode
    }
    this.block.pop = await createProof(payload, this.jwkPairOrig.privateJwk)
    return this.block.pop
  }

  private _checkInit (): void {
    if (!this.checked) {
      throw new Error('NOT INITIALIZED. Before calling any other method, initialize this instance of NonRepudiationOrig calling async method init()')
    }
  }
}
