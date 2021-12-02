import { JWK, JWTVerifyResult } from 'jose'
import { jweDecrypt } from './jwe'
import { HASH_ALG } from './constants'
import { createProof } from './createProof'
import { DataExchange, DataExchangeInit, JwkPair, PoOPayload, PoPPayload, PoRPayload } from './types'
import { sha } from './sha'
import { verifyKeyPair } from './verifyKeyPair'
import { verifyProof } from './verifyProof'

interface Block {
  jwe: string
  decrypted?: Uint8Array
  secret?: JWK
  poo?: string
  por?: string
  pop?: string
}

export class NonRepudiationDest {
  dataExchange: DataExchangeInit
  jwkPairDest: JwkPair
  publicJwkOrig: JWK
  block?: Block
  checked: boolean

  constructor (dataExchangeId: DataExchange['id'], jwkPairDest: JwkPair, publicJwkOrig: JWK) {
    this.jwkPairDest = jwkPairDest
    this.publicJwkOrig = publicJwkOrig
    this.dataExchange = {
      id: dataExchangeId,
      orig: JSON.stringify(this.publicJwkOrig),
      dest: JSON.stringify(this.jwkPairDest.publicJwk),
      hashAlg: HASH_ALG
    }
    this.checked = false
  }

  async init (): Promise<void> {
    await verifyKeyPair(this.jwkPairDest.publicJwk, this.jwkPairDest.privateJwk)
    this.checked = true
  }

  async verifyPoO (poo: string, cipherblock: string): Promise<JWTVerifyResult> {
    this._checkInit()

    const dataExchange: DataExchangeInit = {
      ...this.dataExchange,
      cipherblockDgst: await sha(cipherblock, this.dataExchange.hashAlg)
    }
    const expectedPayloadClaims: PoOPayload = {
      proofType: 'PoO',
      iss: 'orig',
      dataExchange
    }
    const verified = await verifyProof(poo, this.publicJwkOrig, expectedPayloadClaims)

    this.block = {
      jwe: cipherblock,
      poo: poo
    }

    this.dataExchange = (verified.payload as PoOPayload).dataExchange

    return verified
  }

  /**
   * Creates the proof of reception (PoR) as a compact JWS for the block of data. Besides returning its value, it is also stored in this.block.por
   *
   */
  async generatePoR (): Promise<string> {
    this._checkInit()

    if (this.block?.poo === undefined) {
      throw new Error('Before computing a PoR, you have first to receive a valid cipherblock with a PoO and validate the PoO')
    }

    const payload: PoRPayload = {
      proofType: 'PoR',
      iss: 'dest',
      dataExchange: this.dataExchange,
      pooDgst: await sha(this.block.poo)
    }
    this.block.por = await createProof(payload, this.jwkPairDest.privateJwk)
    return this.block.por
  }

  async verifyPoPAndDecrypt (pop: string, secret: string, verificationCode: string): Promise<{verified: JWTVerifyResult, decryptedBlock: Uint8Array}> {
    this._checkInit()

    if (this.block?.por === undefined) {
      throw new Error('Cannot verify a PoP if not even a PoR have been created')
    }

    const decryptedBlock = (await jweDecrypt(this.block.jwe, JSON.parse(secret))).plaintext
    const decryptedDgst = await sha(decryptedBlock)
    if (decryptedDgst !== this.dataExchange.blockCommitment) {
      throw new Error('Decrypted block does not meet the committed one')
    }
    this.block.secret = JSON.parse(secret)
    this.block.decrypted = decryptedBlock

    const expectedPayloadClaims: PoPPayload = {
      proofType: 'PoP',
      iss: 'orig',
      dataExchange: this.dataExchange,
      porDgst: await sha(this.block.por),
      secret,
      verificationCode
    }
    const verified = await verifyProof(pop, this.publicJwkOrig, expectedPayloadClaims)
    this.block.pop = pop

    return { verified, decryptedBlock }
  }

  private _checkInit (): void {
    if (!this.checked) {
      throw new Error('NOT INITIALIZED. Before calling any other method, initialize this instance of NonRepudiationOrig calling async method init()')
    }
  }
}
