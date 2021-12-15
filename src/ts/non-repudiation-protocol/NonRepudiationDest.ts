import * as b64 from '@juanelas/base64'
import { bufToHex } from 'bigint-conversion'
import { ethers } from 'ethers'
import { SignJWT } from 'jose'
import { generateVerificationRequest } from '../conflict-resolution/'
import { importJwk, jweDecrypt, jwsDecode, oneTimeSecret, verifyKeyPair } from '../crypto/'
import { defaultDltConfig, getSecretFromLedger } from '../dlt/'
import { exchangeId } from '../exchange'
import { NrError } from '../errors'
import { createProof, verifyProof } from '../proofs/'
import { checkIssuedAt, parseHex, sha } from '../utils/'
import { Block, DataExchange, DataExchangeAgreement, DisputeRequestPayload, DltConfig, JWK, JwkPair, JwsHeaderAndPayload, PoOInputPayload, PoOPayload, PoPInputPayload, PoPPayload, PoRInputPayload, Dict, StoredProof, TimestampVerifyOptions } from './../types'

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
  private readonly initialized: Promise<boolean>

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

  private async init (): Promise<void> {
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
  async verifyPoO (poo: string, cipherblock: string, clockToleranceMs?: number, currentDate?: Date): Promise<JwsHeaderAndPayload<PoOPayload>> {
    await this.initialized

    const cipherblockDgst = b64.encode(await sha(cipherblock, this.agreement.hashAlg), true, false)

    const { payload } = await jwsDecode<PoOPayload>(poo)

    const dataExchangePreview: Omit<DataExchange, 'id'> = {
      ...this.agreement,
      cipherblockDgst,
      blockCommitment: payload.exchange.blockCommitment,
      secretCommitment: payload.exchange.secretCommitment
    }

    const dataExchange: DataExchange = {
      ...dataExchangePreview,
      id: await exchangeId(dataExchangePreview)
    }

    const expectedPayloadClaims: PoOInputPayload = {
      proofType: 'PoO',
      iss: 'orig',
      exchange: dataExchange
    }

    const proofVerifyOptions: TimestampVerifyOptions = {}
    if (clockToleranceMs !== undefined) proofVerifyOptions.clockToleranceMs = clockToleranceMs
    if (currentDate !== undefined) proofVerifyOptions.currentTimestamp = currentDate.valueOf()

    const verified = await verifyProof<PoOPayload>(poo, expectedPayloadClaims, proofVerifyOptions)

    this.block = {
      jwe: cipherblock,
      poo: {
        jws: poo,
        payload: verified.payload
      }
    }

    this.exchange = verified.payload.exchange

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
  async verifyPoP (pop: string, clockToleranceMs?: number, currentDate?: Date): Promise<JwsHeaderAndPayload<PoPPayload>> {
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

    const verified = await verifyProof<PoPPayload>(pop, expectedPayloadClaims, proofVerifyOptions)

    const secret: JWK = JSON.parse(verified.payload.secret)

    this.block.secret = {
      hex: bufToHex(b64.decode(secret.k as string) as Uint8Array),
      jwk: secret
    }
    this.block.pop = {
      jws: pop,
      payload: verified.payload
    }

    return verified
  }

  /**
   * Just in case the PoP is not received, the secret can be downloaded from the ledger.
   * The secret should be downloaded before poo.iat + pooToPop max delay.
   *
   * @returns the secret
   */
  async getSecretFromLedger (): Promise<{hex: string, jwk: JWK}> {
    await this.initialized

    if (this.exchange === undefined || this.block.poo === undefined || this.block.por === undefined) {
      throw new Error('Cannot get secret if a PoR has not been sent before')
    }
    const currentTimestamp = Date.now()
    const maxTimeForSecret = this.block.poo.payload.iat * 1000 + this.agreement.pooToSecretDelay
    const timeout = Math.round((maxTimeForSecret - currentTimestamp) / 1000)

    const { hex: secretHex, iat } = await getSecretFromLedger(this.dltContract, this.agreement.ledgerSignerAddress, this.exchange.id, timeout)

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
      throw new Error(`Although the secret has been obtained (and you could try to decrypt the cipherblock), it's been published later than agreed: ${(new Date(iat * 1000)).toUTCString()} > ${(new Date(this.block.poo.payload.iat * 1000 + this.agreement.pooToSecretDelay)).toUTCString()}`)
    }

    return this.block.secret
  }

  /**
   * Decrypts the cipherblock once all the previous proofs have been verified
   * @returns the decrypted block
   */
  async decrypt (): Promise<Uint8Array> {
    await this.initialized

    if (this.exchange === undefined) {
      throw new Error('No agreed exchange')
    }
    if (this.block.secret?.jwk === undefined) {
      throw new Error('Cannot decrypt without the secret')
    }
    if (this.block.jwe === undefined) {
      throw new Error('No cipherblock to decrypt')
    }

    const decryptedBlock = (await jweDecrypt(this.block.jwe, this.block.secret.jwk)).plaintext
    const decryptedDgst = b64.encode(await sha(decryptedBlock, this.agreement.hashAlg), true, false)
    if (decryptedDgst !== this.exchange.blockCommitment) {
      throw new Error('Decrypted block does not meet the committed one')
    }
    this.block.raw = decryptedBlock

    return decryptedBlock
  }

  /**
   * Generates a verification request that can be used to query the
   * Conflict-Resolver Service for completeness of the non-repudiation protocol
   *
   * @returns the verification request as a compact JWS signed with 'dest's private key
   */
  async generateVerificationRequest (): Promise<string> {
    await this.initialized

    if (this.block.por === undefined || this.exchange === undefined) {
      throw new Error('Before generating a VerificationRequest, you have first to hold a valid PoR for the exchange')
    }

    return await generateVerificationRequest('dest', this.exchange.id, this.block.por.jws, this.jwkPairDest.privateJwk)
  }

  /**
   * Generates a dispute request that can be used to query the
   * Conflict-Resolver Service regarding impossibility to decrypt the cipherblock with the received secret
   *
   * @returns the dispute request as a compact JWS signed with 'dest's private key
   */
  async generateDisputeRequest (): Promise<string> {
    await this.initialized

    if (this.block.por === undefined || this.block.jwe === undefined || this.exchange === undefined) {
      throw new Error('Before generating a VerificationRequest, you have first to hold a valid PoR for the exchange and have received the cipherblock')
    }

    const payload: Dict<DisputeRequestPayload> = {
      iss: 'dest',
      por: this.block.por.jws,
      type: 'disputeRequest',
      cipherblock: this.block.jwe,
      iat: Math.floor(Date.now() / 1000),
      dataExchangeId: this.exchange.id
    }

    const privateKey = await importJwk(this.jwkPairDest.privateJwk)

    try {
      const jws = await new SignJWT(payload)
        .setProtectedHeader({ alg: this.jwkPairDest.privateJwk.alg })
        .setIssuedAt(payload.iat)
        .sign(privateKey)
      return jws
    } catch (error) {
      throw new NrError(error, ['unexpected error'])
    }
  }
}
