import { ethers } from 'ethers'
import { JWK, JWTVerifyResult } from 'jose'
import { hexToBuf } from 'bigint-conversion'
import * as base64 from '@juanelas/base64'

import { jweEncrypt } from './jwe'
import { createProof } from './createProof'
import { oneTimeSecret } from './oneTimeSecret'
import { Algs, ContractConfig, DataExchange, DataExchangeInit, DltConfig, JwkPair, OrigBlock, PoOPayload, PoPPayload, PoRPayload } from './types'
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
  initialized: Promise<boolean>

  /**
   * @param exchangeId - the id of this data exchange. It MUST be unique for the sender
   * @param jwkPairOrig - a pair of private and public keys owned by this entity (non-repudiation orig)
   * @param publicJwkDest - the public key as a JWK of the other peer (non-repudiation dest)
   * @param block - the block of data to transmit in this data exchange
   * @param dltConfig - an object with the necessary configuration for the (Ethereum-like) DLT
   * @param algs - is used to overwrite the default algorithms for hash (SHA-256), signing (ES256) and encryption (A256GCM)
   */
  constructor (exchangeId: DataExchange['id'], jwkPairOrig: JwkPair, publicJwkDest: JWK, block: Uint8Array, dltConfig?: Partial<DltConfig>, algs?: Algs) {
    this.jwkPairOrig = jwkPairOrig
    this.publicJwkDest = publicJwkDest
    if (this.jwkPairOrig.privateJwk.alg === undefined || this.jwkPairOrig.publicJwk.alg === undefined || this.publicJwkDest.alg === undefined) {
      throw new TypeError('"alg" argument is required, please add it to your JWKs first')
    }

    this.exchange = {
      id: exchangeId,
      orig: JSON.stringify(this.jwkPairOrig.publicJwk),
      dest: JSON.stringify(this.publicJwkDest),
      hashAlg: 'SHA-256',
      signingAlg: 'ES256',
      encAlg: 'A256GCM',
      ledgerSignerAddress: '',
      ledgerContract: '',
      ...algs
    }

    // @ts-expect-error I will end assigning the complete Block in the async init()
    this.block = {
      raw: block
    }

    // @ts-expect-error I will end assigning the complete Block in the async init()
    this.dltConfig = dltConfig

    this.initialized = new Promise((resolve, reject) => {
      this.init().then(() => {
        resolve(true)
      }).catch((error) => {
        throw error
      })
    })
  }

  /**
   * Initialize this instance. It MUST be invoked before calling any other method.
   */
  async init (): Promise<void> {
    await verifyKeyPair(this.jwkPairOrig.publicJwk, this.jwkPairOrig.privateJwk)

    const secret = await oneTimeSecret(this.exchange.encAlg)
    this.block = {
      ...this.block,
      secret,
      jwe: await jweEncrypt(this.exchange.id, this.block.raw, secret.jwk, this.exchange.encAlg)
    }

    this.exchange = {
      ...this.exchange,
      cipherblockDgst: await sha(this.block.jwe, this.exchange.hashAlg),
      blockCommitment: await sha(this.block.raw, this.exchange.hashAlg),
      secretCommitment: await sha(new Uint8Array(hexToBuf(this.block.secret.hex)), this.exchange.hashAlg)
    }

    await this._dltSetup()
  }

  private async _dltSetup (): Promise<void> {
    const dltConfig = {
      // @ts-expect-error I will end assigning the complete Block in the async init()
      gasLimit: 12500000,
      // @ts-expect-error I will end assigning the complete Block in the async init()
      rpcProviderUrl: '***REMOVED***',
      // @ts-expect-error I will end assigning the complete Block in the async init()
      disable: false,
      ...this.dltConfig
    }
    if (!dltConfig.disable) {
      dltConfig.contractConfig = dltConfig.contractConfig ?? (contractConfigDefault as ContractConfig)
      const rpcProvider = new ethers.providers.JsonRpcProvider(dltConfig.rpcProviderUrl)
      if (this.jwkPairOrig.privateJwk.d === undefined) {
        throw new Error('INVALID SIGNING ALGORITHM: No d property found on private key')
      }
      const privateKey: Uint8Array = base64.decode(this.jwkPairOrig.privateJwk.d) as Uint8Array
      const signingKey = new ethers.utils.SigningKey(privateKey)
      const signer = new ethers.Wallet(signingKey, rpcProvider)
      dltConfig.signer = { address: await signer.getAddress(), signer }
      dltConfig.contract = new ethers.Contract(dltConfig.contractConfig.address, dltConfig.contractConfig.abi, signer)
      this.exchange.ledgerSignerAddress = dltConfig.signer.address
      this.exchange.ledgerContract = dltConfig.contractConfig.address
    }
    this.dltConfig = dltConfig
  }

  /**
   * Creates the proof of origin (PoO).
   * Besides returning its value, it is also stored in this.block.poo
   *
   * @returns a compact JWS with the PoO
   */
  async generatePoO (): Promise<string> {
    await this.initialized

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
    await this.initialized

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
    await this.initialized

    if (this.block.por === undefined) {
      throw new Error('Before computing a PoP, you have first to have received and verified the PoR')
    }

    let verificationCode = 'verificationCode'
    if (!this.dltConfig.disable) {
      const secret = ethers.BigNumber.from(`0x${this.block.secret.hex}`)

      // TO-DO: it fails because the account hasn't got any funds (ether). Do we have a faucet? Set gas prize to 0?
      const setRegistryTx = await this.dltConfig.contract?.setRegistry(this.exchange.id, secret, { gasLimit: this.dltConfig.gasLimit })
      verificationCode = JSON.stringify(setRegistryTx)

      // TO-DO: I would say that we can remove the next wait
      await setRegistryTx.wait()

      // TO-DO: Next line is completely useless. Here for testing but we could remove it.
      await this.dltConfig.contract?.registry(this.dltConfig.signer?.address, this.exchange.id)
    }

    const payload: PoPPayload = {
      proofType: 'PoP',
      iss: 'orig',
      exchange: this.exchange,
      porDgst: await sha(this.block.por, this.exchange.hashAlg),
      secret: JSON.stringify(this.block.secret.jwk),
      verificationCode
    }
    this.block.pop = await createProof(payload, this.jwkPairOrig.privateJwk)
    return this.block.pop
  }
}
