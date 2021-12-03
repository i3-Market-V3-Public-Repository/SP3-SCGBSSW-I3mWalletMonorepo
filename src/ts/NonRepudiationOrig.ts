import { ethers } from 'ethers'
import { JWK, JWTVerifyResult } from 'jose'

import { jweEncrypt } from './jwe'
import { HASH_ALG } from './constants'
import { createProof } from './createProof'
import { oneTimeSecret } from './oneTimeSecret'
import { ContractConfig, DataExchange, DataExchangeInit, DltConfig, JwkPair, OrigBlock, PoOPayload, PoPPayload, PoRPayload } from './types'
import { sha } from './sha'
import { verifyKeyPair } from './verifyKeyPair'
import { verifyProof } from './verifyProof'

import contractConfigDefault from '../besu/NonRepudiation'

/**
 * The base class that should be instantiated by the origin of a data
 * exchange when non-repudiation is required. In the i3-MARKET ecosystem it is
 * likely to be a Provider.
 */
export class NonRepudiationOrig {
  exchange: DataExchangeInit
  jwkPairOrig: JwkPair
  publicJwkDest: JWK
  block: OrigBlock
  dltConfig: DltConfig
  checked: boolean

  /**
   * @param exchangeId - the id of this data exchange. It MUST be unique for the sender
   * @param jwkPairOrig - a pair of private and public keys owned by this entity (non-repudiation orig)
   * @param publicJwkDest - the public key as a JWK of the other peer (non-repudiation dest)
   * @param block - the block of data to transmit in this data exchange
   * @param dltConfig - an object with the necessary configuration for the (Ethereum-like) DLT
   */
  constructor (exchangeId: DataExchange['id'], jwkPairOrig: JwkPair, publicJwkDest: JWK, block: Uint8Array, dltConfig?: DltConfig) {
    this.jwkPairOrig = jwkPairOrig
    this.publicJwkDest = publicJwkDest
    if (this.jwkPairOrig.privateJwk.alg === undefined || this.jwkPairOrig.publicJwk.alg === undefined || this.publicJwkDest.alg === undefined) {
      throw new TypeError('"alg" argument is required, please add it to your JWKs first')
    }

    this.exchange = {
      id: exchangeId,
      orig: JSON.stringify(this.jwkPairOrig.publicJwk),
      dest: JSON.stringify(this.publicJwkDest),
      hashAlg: HASH_ALG
    }
    this.block = {
      raw: block
    }

    this.dltConfig = this._dltSetup(dltConfig)

    this.checked = false
  }

  private _dltSetup (providedDltConfig?: DltConfig): DltConfig {
    const dltConfig = {
      gasLimit: 12500000,
      rpcProviderUrl: '***REMOVED***',
      disable: false,
      ...providedDltConfig
    }
    if (!dltConfig.disable) {
      dltConfig.contractConfig = dltConfig.contractConfig ?? (contractConfigDefault as ContractConfig)
      const rpcProvider = new ethers.providers.JsonRpcProvider(dltConfig.rpcProviderUrl)

      /** TODO: it should be jwkPairDest.privateJwk */
      const privKeyHex = '***REMOVED***'

      const signer = new ethers.Wallet(privKeyHex, rpcProvider)
      dltConfig.contract = new ethers.Contract(dltConfig.contractConfig.address, dltConfig.contractConfig.abi, signer)
    }

    return dltConfig
  }

  /**
   * Initialize this instance. It MUST be invoked before calling any other method.
   */
  async init (): Promise<void> {
    await verifyKeyPair(this.jwkPairOrig.publicJwk, this.jwkPairOrig.privateJwk)

    this.block.secret = await oneTimeSecret()
    const secretStr = JSON.stringify(this.block.secret)
    this.block.jwe = await jweEncrypt(this.exchange.id, this.block.raw, this.block.secret)

    this.exchange = {
      ...this.exchange,
      cipherblockDgst: await sha(this.block.jwe, this.exchange.hashAlg),
      blockCommitment: await sha(this.block.raw, this.exchange.hashAlg),
      secretCommitment: await sha(secretStr, this.exchange.hashAlg)
    }

    this.checked = true
  }

  /**
   * Creates the proof of origin (PoO).
   * Besides returning its value, it is also stored in this.block.poo
   *
   * @returns a compact JWS with the PoO
   */
  async generatePoO (): Promise<string> {
    this._checkInit()

    const payload: PoOPayload = {
      proofType: 'PoO',
      iss: 'orig',
      exchange: this.exchange
    }
    this.block.poo = await createProof(payload, this.jwkPairOrig.privateJwk)
    return this.block.poo
  }

  /**
   * Verifies a proof of reception.
   * If verification passes, `por` is added to `this.block`
   *
   * @param por - A PoR in caompact JWS format
   * @returns the verified payload and protected header
   */
  async verifyPoR (por: string): Promise<JWTVerifyResult> {
    this._checkInit()

    if (this.block?.poo === undefined) {
      throw new Error('Cannot verify a PoR if not even a PoO have been created')
    }

    const expectedPayloadClaims: PoRPayload = {
      proofType: 'PoR',
      iss: 'dest',
      exchange: this.exchange,
      pooDgst: await sha(this.block.poo, this.exchange.hashAlg)
    }
    const verified = await verifyProof(por, this.publicJwkDest, expectedPayloadClaims)
    this.block.por = por

    return verified
  }

  /**
   * Creates the proof of publication (PoP).
   * Besides returning its value, it is also stored in `this.block.pop`
   *
   * @returns a compact JWS with the PoP
   */
  async generatePoP (): Promise<string> {
    this._checkInit()

    if (this.block?.por === undefined) {
      throw new Error('Before computing a PoP, you have first to receive a verify a PoR')
    }

    /**
     * TO-DO: obtain verification code from the blockchain
     * TO-DO: Pass secret to raw hex
     */
    let verificationCode = 'verificationCode'
    if (this.dltConfig.disable !== true) {
      const secretHex = '1234567890'

      const setRegistryTx = await this.dltConfig.contract?.setRegistry(this.exchange.id, secretHex, { gasLimit: this.dltConfig.gasLimit })

      await setRegistryTx.wait()

      const address = await this.dltConfig.contract?.signer.getAddress()
      verificationCode = await this.dltConfig.contract?.registry(address, this.exchange.id)
    }

    const payload: PoPPayload = {
      proofType: 'PoP',
      iss: 'orig',
      exchange: this.exchange,
      porDgst: await sha(this.block.por, this.exchange.hashAlg),
      secret: JSON.stringify(this.block.secret),
      verificationCode
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
