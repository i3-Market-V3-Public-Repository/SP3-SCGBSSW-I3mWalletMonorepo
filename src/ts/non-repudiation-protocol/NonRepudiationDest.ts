import * as b64 from '@juanelas/base64'
import { bufToHex } from 'bigint-conversion'
import { JWTPayload, SignJWT } from 'jose'
import { generateVerificationRequest } from '../conflict-resolution/'
import { importJwk, jweDecrypt, jwsDecode, oneTimeSecret, verifyKeyPair } from '../crypto/'
import { NrpDltAgentDest } from '../dlt/'
import { NrError } from '../errors'
import { exchangeId, parseAgreement } from '../exchange'
import { createProof, verifyProof } from '../proofs/'
import { checkTimestamp, parseHex, sha } from '../utils/'
import { Block, DataExchange, DataExchangeAgreement, DecodedProof, Dict, DisputeRequestPayload, JWK, JwkPair, PoOPayload, PoPPayload, PoRPayload, StoredProof, TimestampVerifyOptions } from './../types'

/**
 * The base class that should be instantiated by the destination of a data
 * exchange when non-repudiation is required. In the i3-MARKET ecosystem it is
 * likely to be a Consumer.
 */
export class NonRepudiationDest {
  agreement!: DataExchangeAgreement
  exchange?: DataExchange
  jwkPairDest!: JwkPair
  publicJwkOrig!: JWK
  block!: Block
  dltAgent!: NrpDltAgentDest
  readonly initialized: Promise<boolean>

  /**
   * @param agreement - a DataExchangeAgreement
   * @param privateJwk - the private key that will be used to sign the proofs
   * @param dltAgent - a DLT agent providing read connection to the ledger
   */
  constructor (agreement: DataExchangeAgreement, privateJwk: JWK, dltAgent: NrpDltAgentDest) {
    this.initialized = new Promise((resolve, reject) => {
      this.asyncConstructor(agreement, privateJwk, dltAgent).then(() => {
        resolve(true)
      }).catch((error) => {
        reject(error)
      })
    })
  }

  private async asyncConstructor (agreement: DataExchangeAgreement, privateJwk: JWK, dltAgent: NrpDltAgentDest): Promise<void> {
    this.agreement = await parseAgreement(agreement)

    this.jwkPairDest = {
      privateJwk: privateJwk,
      publicJwk: JSON.parse(agreement.dest) as JWK
    }
    this.publicJwkOrig = JSON.parse(agreement.orig) as JWK

    await verifyKeyPair(this.jwkPairDest.publicJwk, this.jwkPairDest.privateJwk)

    this.dltAgent = dltAgent

    const contractAddress = parseHex(await this.dltAgent.getContractAddress(), true)
    if (this.agreement.ledgerContractAddress !== contractAddress) {
      throw new Error(`Contract address ${contractAddress} does not meet agreed one ${this.agreement.ledgerContractAddress}`)
    }

    this.block = {}
  }

  /**
   * Verifies a proof of origin against the received cipherblock.
   * If verification passes, `pop` and `cipherblock` are added to this.block
   *
   * @param poo - a Proof of Origin (PoO) in compact JWS format
   * @param cipherblock - a cipherblock as a JWE
   * @param options - time verification options
   * @returns the verified payload and protected header
   *
   */
  async verifyPoO (poo: string, cipherblock: string, options?: Pick<TimestampVerifyOptions, 'timestamp' | 'tolerance'>): Promise<DecodedProof<PoOPayload>> {
    await this.initialized

    const cipherblockDgst = b64.encode(await sha(cipherblock, this.agreement.hashAlg), true, false)

    const { payload } = await jwsDecode<Dict<PoOPayload>>(poo)

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

    const expectedPayloadClaims: Omit<PoOPayload, 'iat'> = {
      proofType: 'PoO',
      iss: 'orig',
      exchange: dataExchange
    }

    const currentTimestamp = Date.now()
    const opts: TimestampVerifyOptions = {
      timestamp: currentTimestamp,
      notBefore: 'iat',
      notAfter: 'iat',
      ...options
    }
    const verified = await verifyProof<PoOPayload>(poo, expectedPayloadClaims, opts)

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
  async generatePoR (): Promise<StoredProof<PoRPayload>> {
    await this.initialized

    if (this.exchange === undefined || this.block.poo === undefined) {
      throw new Error('Before computing a PoR, you have first to receive a valid cipherblock with a PoO and validate the PoO')
    }

    const payload: Omit<PoRPayload, 'iat'> = {
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
   * @param options - time related options for verification
   * @returns the verified payload (that includes the secret that can be used to decrypt the cipherblock) and protected header
   */
  async verifyPoP (pop: string, options?: Pick<TimestampVerifyOptions, 'timestamp' | 'tolerance'>): Promise<DecodedProof<PoPPayload>> {
    await this.initialized

    if (this.exchange === undefined || this.block.por === undefined || this.block.poo === undefined) {
      throw new Error('Cannot verify a PoP if not even a PoR have been created')
    }

    const expectedPayloadClaims: Omit<PoPPayload, 'iat'> = {
      proofType: 'PoP',
      iss: 'orig',
      exchange: this.exchange,
      por: this.block.por.jws,
      secret: '',
      verificationCode: ''
    }

    const opts: TimestampVerifyOptions = {
      timestamp: Date.now(),
      notBefore: 'iat',
      notAfter: this.block.poo.payload.iat * 1000 + this.exchange.pooToPopDelay,
      ...options
    }

    const verified = await verifyProof<PoPPayload>(pop, expectedPayloadClaims, opts)

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

    const { hex: secretHex, iat } = await this.dltAgent.getSecretFromLedger(this.agreement.ledgerSignerAddress, this.exchange.id, timeout)

    this.block.secret = await oneTimeSecret(this.exchange.encAlg, secretHex)

    try {
      checkTimestamp(iat * 1000, this.block.por.payload.iat * 1000, this.block.poo.payload.iat * 1000 + this.exchange.pooToSecretDelay)
    } catch (error) {
      throw new NrError(`Although the secret has been obtained (and you could try to decrypt the cipherblock), it's been published later than agreed: ${(new Date(iat * 1000)).toUTCString()} > ${(new Date(this.block.poo.payload.iat * 1000 + this.agreement.pooToSecretDelay)).toUTCString()}`, ['secret not published in time'])
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

    const payload: DisputeRequestPayload = {
      proofType: 'request',
      iss: 'dest',
      por: this.block.por.jws,
      type: 'disputeRequest',
      cipherblock: this.block.jwe,
      iat: Math.floor(Date.now() / 1000),
      dataExchangeId: this.exchange.id
    }

    const privateKey = await importJwk(this.jwkPairDest.privateJwk)

    try {
      const jws = await new SignJWT(payload as unknown as JWTPayload)
        .setProtectedHeader({ alg: this.jwkPairDest.privateJwk.alg })
        .setIssuedAt(payload.iat)
        .sign(privateKey)
      return jws
    } catch (error) {
      throw new NrError(error, ['unexpected error'])
    }
  }
}
