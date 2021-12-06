import * as b64 from '@juanelas/base64'
import { bufToHex } from 'bigint-conversion'
import { ethers } from 'ethers'
import { JWK, JWTVerifyResult } from 'jose'

import { jweDecrypt } from './jwe'
import { createProof } from './createProof'
import { oneTimeSecret } from './oneTimeSecret'
import { Algs, Block, ContractConfig, DataExchange, DataExchangeInit, DltConfig, JwkPair, PoOPayload, PoPPayload, PoRPayload } from './types'
import { sha } from './sha'
import { verifyKeyPair } from './verifyKeyPair'
import { verifyProof } from './verifyProof'

/** TO-DO: Could the json be imported from an npm package? */
import contractConfigDefault from '../besu/NonRepudiation.json'

/**
 * The base class that should be instantiated by the destination of a data
 * exchange when non-repudiation is required. In the i3-MARKET ecosystem it is
 * likely to be a Consumer.
 */
export class NonRepudiationDest {
  exchange: DataExchangeInit
  jwkPairDest: JwkPair
  publicJwkOrig: JWK
  block: Block
  dltConfig: DltConfig
  initialized: Promise<boolean>

  /**
   *
   * @param exchangeId - the id of this data exchange. It is a unique identifier as the base64url-no-padding encoding of a uint256
   * @param jwkPairDest - a pair of private and public keys owned by this entity (non-repudiation dest)
   * @param publicJwkOrig - the public key as a JWK of the other peer (non-repudiation orig)
   * @param dltConfig - an object with the necessary configuration for the (Ethereum-like) DLT
   * @param algs - is used to overwrite the default algorithms for hash (SHA-256), signing (ES256) and encryption (A256GM)
   */
  constructor (exchangeId: DataExchange['id'], jwkPairDest: JwkPair, publicJwkOrig: JWK, dltConfig?: Partial<DltConfig>, algs?: Algs) {
    this.jwkPairDest = jwkPairDest
    this.publicJwkOrig = publicJwkOrig
    this.exchange = {
      id: exchangeId,
      orig: JSON.stringify(this.publicJwkOrig),
      dest: JSON.stringify(this.jwkPairDest.publicJwk),
      hashAlg: 'SHA-256',
      signingAlg: 'ES256',
      encAlg: 'A256GCM',
      ledgerContract: '',
      ledgerSignerAddress: '',
      ...algs
    }
    this.block = {}
    this.dltConfig = this._dltSetup(dltConfig)
    this.initialized = new Promise((resolve, reject) => {
      this.init().then(() => {
        resolve(true)
      }).catch((error) => {
        reject(error)
      })
    })
  }

  private _dltSetup (providedDltConfig?: Partial<DltConfig>): DltConfig {
    const dltConfig = {
      gasLimit: 12500000,
      rpcProviderUrl: '***REMOVED***',
      disable: false,
      ...providedDltConfig
    }
    if (!dltConfig.disable) {
      dltConfig.contractConfig = dltConfig.contractConfig ?? (contractConfigDefault as ContractConfig)
      const rpcProvider = new ethers.providers.JsonRpcProvider(dltConfig.rpcProviderUrl)
      dltConfig.contract = new ethers.Contract(dltConfig.contractConfig.address, dltConfig.contractConfig.abi, rpcProvider)
    }
    return dltConfig as DltConfig
  }

  /**
   * Initialize this instance. It MUST be invoked before calling any other method.
   */
  async init (): Promise<void> {
    await verifyKeyPair(this.jwkPairDest.publicJwk, this.jwkPairDest.privateJwk)
  }

  /**
   * Verifies a proof of origin against the received cipherblock.
   * If verification passes, `pop` and `cipherblock` are added to this.block
   *
   * @param poo - a Proof of Origin (PoO) in compact JWS format
   * @param cipherblock - a cipherblock as a JWE
   * @returns the verified payload and protected header
   *
   */
  async verifyPoO (poo: string, cipherblock: string): Promise<JWTVerifyResult> {
    await this.initialized

    const dataExchange: DataExchangeInit = {
      ...this.exchange,
      cipherblockDgst: await sha(cipherblock, this.exchange.hashAlg)
    }
    const expectedPayloadClaims: PoOPayload = {
      proofType: 'PoO',
      iss: 'orig',
      exchange: dataExchange
    }
    const verified = await verifyProof(poo, this.publicJwkOrig, expectedPayloadClaims)

    this.block = {
      jwe: cipherblock,
      poo: poo
    }

    this.exchange = (verified.payload as PoOPayload).exchange

    return verified
  }

  /**
   * Creates the proof of reception (PoR).
   * Besides returning its value, it is also stored in `this.block.por`
   *
   * @returns a compact JWS with the PoR
   */
  async generatePoR (): Promise<string> {
    await this.initialized

    if (this.block.poo === undefined) {
      throw new Error('Before computing a PoR, you have first to receive a valid cipherblock with a PoO and validate the PoO')
    }

    const payload: PoRPayload = {
      proofType: 'PoR',
      iss: 'dest',
      exchange: this.exchange,
      poo: this.block.poo
    }
    this.block.por = await createProof(payload, this.jwkPairDest.privateJwk)
    return this.block.por
  }

  /**
   * Verifies a received Proof of Publication (PoP) and returns the secret
   * @param pop - a PoP in compact JWS
   * @param secret - the JWK secret that was used to encrypt the block
   * @returns the verified payload (that includes the secret that can be used to decrypt the cipherblock) and protected header
   */
  async verifyPoP (pop: string): Promise<JWTVerifyResult> {
    await this.initialized

    if (this.block.por === undefined) {
      throw new Error('Cannot verify a PoP if not even a PoR have been created')
    }

    const expectedPayloadClaims: PoPPayload = {
      proofType: 'PoP',
      iss: 'orig',
      exchange: this.exchange,
      por: this.block.por,
      secret: '',
      verificationCode: ''
    }
    const verified = await verifyProof(pop, this.publicJwkOrig, expectedPayloadClaims)

    const secret: JWK = JSON.parse((verified.payload as PoPPayload).secret)

    this.block.secret = {
      hex: bufToHex(b64.decode(secret.k as string) as Uint8Array),
      jwk: secret
    }
    this.block.pop = pop

    return verified
  }

  /**
   * Just in case the PoP is not received, the secret can be downloaded from the ledger
   *
   * @param timeout - the time in seconds to wait for the query to get the value
   *
   * @returns the secret
   */
  async getSecretFromLedger (timeout: number = 20): Promise<{hex: string, jwk: JWK}> {
    let secretBn = ethers.BigNumber.from(0)
    let counter = 0
    do {
      secretBn = await this.dltConfig.contract.registry(this.exchange.ledgerSignerAddress, ethers.BigNumber.from(b64.decode(this.exchange.id)))
      if (secretBn.isZero()) {
        counter++
        await new Promise(resolve => setTimeout(resolve, 1000))
      }
    } while (secretBn.isZero() && counter < timeout)
    if (secretBn.isZero()) {
      throw new Error(`timeout of ${timeout}s exceeded when querying the ledger`)
    }
    const secretHex = secretBn.toHexString()

    this.block.secret = await oneTimeSecret(this.exchange.encAlg, secretHex)
    return this.block.secret
  }

  /**
   * Decrypts the cipherblock once all the previous proofs have been verified
   * @returns the decrypted block
   *
   * @throws Error if the previous proofs have not been verified or the decrypted block does not meet the committed one
   */
  async decrypt (): Promise<Uint8Array> {
    await this.initialized

    if (this.block.secret?.jwk === undefined) {
      throw new Error('Cannot decrypt without the secret')
    }
    if (this.block.jwe === undefined) {
      throw new Error('No cipherblock to decrypt')
    }

    const decryptedBlock = (await jweDecrypt(this.block.jwe, this.block.secret.jwk)).plaintext
    const decryptedDgst = await sha(decryptedBlock, this.exchange.hashAlg)
    if (decryptedDgst !== this.exchange.blockCommitment) {
      throw new Error('Decrypted block does not meet the committed one')
    }
    this.block.raw = decryptedBlock

    return decryptedBlock
  }
}
