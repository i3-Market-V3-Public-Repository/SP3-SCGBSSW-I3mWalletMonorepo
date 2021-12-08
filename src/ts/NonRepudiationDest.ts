import * as b64 from '@juanelas/base64'
import { bufToHex } from 'bigint-conversion'
import { ethers } from 'ethers'
import { hashable } from 'object-sha'
import { checkIssuedAt } from './checkTimestamp'
/** TO-DO: Could the json be imported from an npm package? */
import { createProof } from './createProof'
import { defaultDltConfig } from './defaultDltConfig'
import { jweDecrypt } from './jwe'
import { oneTimeSecret } from './oneTimeSecret'
import { sha } from './sha'
import { Block, DataExchange, DataExchangeAgreement, DltConfig, JWK, JwkPair, JWTVerifyResult, PoOInputPayload, PoPInputPayload, PoPPayload, PoRInputPayload, ProofPayload, StoredProof, TimestampVerifyOptions } from './types'
import { parseHex } from './utils'
import { verifyKeyPair } from './verifyKeyPair'
import { verifyProof } from './verifyProof'

/**
 * The base class that should be instantiated by the destination of a data
 * exchange when non-repudiation is required. In the i3-MARKET ecosystem it is
 * likely to be a Consumer.
 */
export class NonRepudiationDest {
  agreement: DataExchangeAgreement
  exchange?: DataExchange
  jwkPairDest: JwkPair
  publicJwkOrig: JWK
  block: Block
  dltConfig: DltConfig
  dltContract!: ethers.Contract
  initialized: Promise<boolean>

  /**
   * @param agreement - a DataExchangeAgreement
   * @param privateJwk - the private key that will be used to sign the proofs
   * @param dltConfig - an object with the necessary configuration for the (Ethereum-like) DLT
   */
  constructor (agreement: DataExchangeAgreement, privateJwk: JWK, dltConfig?: Partial<DltConfig>) {
    this.jwkPairDest = {
      privateJwk: privateJwk,
      publicJwk: JSON.parse(agreement.dest) as JWK
    }
    this.publicJwkOrig = JSON.parse(agreement.orig) as JWK

    this.agreement = {
      ...agreement,
      ledgerContractAddress: parseHex(agreement.ledgerContractAddress),
      ledgerSignerAddress: parseHex(agreement.ledgerSignerAddress)
    }

    this.block = {}

    this.dltConfig = {
      ...defaultDltConfig,
      ...dltConfig
    }
    this._dltSetup()

    this.initialized = new Promise((resolve, reject) => {
      this.init().then(() => {
        resolve(true)
      }).catch((error) => {
        reject(error)
      })
    })
  }

  private _dltSetup (): void {
    if (!this.dltConfig.disable) {
      const rpcProvider = new ethers.providers.JsonRpcProvider(this.dltConfig.rpcProviderUrl)

      if (this.agreement.ledgerContractAddress !== parseHex(this.dltConfig.contract.address)) {
        throw new Error(`Contract address ${parseHex(this.dltConfig.contract.address)} does not meet agreed one ${this.agreement.ledgerContractAddress}`)
      }

      this.dltContract = new ethers.Contract(this.agreement.ledgerContractAddress, this.dltConfig.contract.abi, rpcProvider)
    }
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
   * @param clockToleranceMs - expected clock tolerance in milliseconds when comparing Dates
   * @param currentDate - check the PoO as it were checked in this date
   * @returns the verified payload and protected header
   *
   */
  async verifyPoO (poo: string, cipherblock: string, clockToleranceMs?: number, currentDate?: Date): Promise<JWTVerifyResult> {
    await this.initialized

    const cipherblockDgst = await sha(cipherblock, this.agreement.hashAlg)

    const id = await sha(hashable({ ...this.agreement, cipherblockDgst }), 'SHA-256')

    const dataExchange: DataExchange = {
      ...this.agreement,
      id,
      cipherblockDgst
    }

    const expectedPayloadClaims: PoOInputPayload = {
      proofType: 'PoO',
      iss: 'orig',
      exchange: dataExchange
    }

    const proofVerifyOptions: TimestampVerifyOptions = {}
    if (clockToleranceMs !== undefined) proofVerifyOptions.clockToleranceMs = clockToleranceMs
    if (currentDate !== undefined) proofVerifyOptions.currentTimestamp = currentDate.valueOf()

    const verified = await verifyProof(poo, this.publicJwkOrig, expectedPayloadClaims, proofVerifyOptions)

    this.block = {
      jwe: cipherblock,
      poo: {
        jws: poo,
        payload: verified.payload as ProofPayload
      }
    }

    this.exchange = (verified.payload as ProofPayload).exchange

    return verified
  }

  /**
   * Creates the proof of reception (PoR).
   * Besides returning its value, it is also stored in `this.block.por`
   *
   * @returns the PoR as a compact JWS along with its decoded payload
   */
  async generatePoR (): Promise<StoredProof> {
    await this.initialized

    if (this.exchange === undefined || this.block.poo === undefined) {
      throw new Error('Before computing a PoR, you have first to receive a valid cipherblock with a PoO and validate the PoO')
    }

    const payload: PoRInputPayload = {
      proofType: 'PoR',
      iss: 'dest',
      exchange: this.exchange,
      poo: this.block.poo.jws
    }

    this.block.por = await createProof(payload, this.jwkPairDest.privateJwk)

    return this.block.por
  }

  /**
   * Verifies a received Proof of Publication (PoP) and returns the secret
   * @param pop - a PoP in compact JWS
   * @param clockToleranceMs - expected clock tolerance in milliseconds when comparing Dates
   * @param currentDate - check the proof as it were checked in this date
   * @returns the verified payload (that includes the secret that can be used to decrypt the cipherblock) and protected header
   */
  async verifyPoP (pop: string, clockToleranceMs?: number, currentDate?: Date): Promise<JWTVerifyResult> {
    await this.initialized

    if (this.exchange === undefined || this.block.por === undefined || this.block.poo === undefined) {
      throw new Error('Cannot verify a PoP if not even a PoR have been created')
    }

    const expectedPayloadClaims: PoPInputPayload = {
      proofType: 'PoP',
      iss: 'orig',
      exchange: this.exchange,
      por: this.block.por.jws,
      secret: '',
      verificationCode: ''
    }

    const proofVerifyOptions: TimestampVerifyOptions = {
      expectedTimestampInterval: {
        min: this.block.poo?.payload.iat * 1000,
        max: this.block.poo?.payload.iat * 1000 + this.exchange.pooToPopDelay
      }
    }
    if (clockToleranceMs !== undefined) proofVerifyOptions.clockToleranceMs = clockToleranceMs
    if (currentDate !== undefined) proofVerifyOptions.currentTimestamp = currentDate.valueOf()

    const verified = await verifyProof(pop, this.publicJwkOrig, expectedPayloadClaims, proofVerifyOptions)

    const secret: JWK = JSON.parse((verified.payload as PoPPayload).secret)

    this.block.secret = {
      hex: bufToHex(b64.decode(secret.k as string) as Uint8Array),
      jwk: secret
    }
    this.block.pop = {
      jws: pop,
      payload: verified.payload as PoPPayload
    }

    return verified
  }

  /**
   * Just in case the PoP is not received, the secret can be downloaded from the ledger.
   * The secret should be downloaded before poo.iat + pooTopop max delay.
   *
   * @returns the secret
   */
  async getSecretFromLedger (): Promise<{hex: string, jwk: JWK}> {
    if (this.exchange === undefined || this.block.poo === undefined || this.block.por === undefined) {
      throw new Error('Cannot get secret if a PoR has not been sent before')
    }
    const currentTimestamp = Date.now()
    const maxTimeForSecret = this.block.poo.payload.iat * 1000 + this.agreement.pooToSecretDelay
    const timeout = Math.round((maxTimeForSecret - currentTimestamp) / 1000)

    let secretBn = ethers.BigNumber.from(0)
    let timestampBn = ethers.BigNumber.from(0)
    let counter = 0
    do {
      ({ secret: secretBn, timestamp: timestampBn } = await this.dltContract.registry(this.agreement.ledgerSignerAddress, `0x${this.exchange.id}`))
      if (secretBn.isZero()) {
        counter++
        await new Promise(resolve => setTimeout(resolve, 1000))
      }
    } while (secretBn.isZero() && counter < timeout)
    if (secretBn.isZero()) {
      throw new Error(`timeout of ${timeout}s exceeded when querying the ledger`)
    }
    const secretHex = secretBn.toHexString()
    const iat = timestampBn.toNumber()

    this.block.secret = await oneTimeSecret(this.exchange.encAlg, secretHex)

    try {
      checkIssuedAt(iat, {
        clockToleranceMs: 0, // The ledger time is what it counts
        expectedTimestampInterval: {
          min: this.block.poo.payload.iat * 1000,
          max: this.block.poo.payload.iat * 1000 + this.agreement.pooToSecretDelay
        }
      })
    } catch (error) {
      throw new Error(`Although the secret has been obtained (you can try to decrypt the cipherblock), it's been published later than agreed: ${(new Date(iat * 1000)).toUTCString()} > ${(new Date(this.block.poo.payload.iat * 1000 + this.agreement.pooToSecretDelay)).toUTCString()}`)
    }

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
    const decryptedDgst = await sha(decryptedBlock, this.agreement.hashAlg)
    if (decryptedDgst !== this.exchange?.blockCommitment) {
      throw new Error('Decrypted block does not meet the committed one')
    }
    this.block.raw = decryptedBlock

    return decryptedBlock
  }
}
