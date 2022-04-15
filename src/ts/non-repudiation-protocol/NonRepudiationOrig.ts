import * as b64 from '@juanelas/base64'
import { hexToBuf } from 'bigint-conversion'
import { generateVerificationRequest } from '../conflict-resolution/'
import { jweEncrypt, oneTimeSecret, verifyKeyPair } from '../crypto/'
import { exchangeId, parseAgreement } from '../exchange'
import { createProof, verifyProof } from '../proofs/'
import { DataExchange, DataExchangeAgreement, JWK, JwkPair, OrigBlock, PoOPayload, PoPPayload, PoRPayload, StoredProof, TimestampVerifyOptions } from '../types'
import { parseHex, sha } from '../utils'
import { NrpDltAgentOrig } from '../dlt/agents'

/**
 * The base class that should be instantiated by the origin of a data
 * exchange when non-repudiation is required. In the i3-MARKET ecosystem it is
 * likely to be a Provider.
 */
export class NonRepudiationOrig {
  agreement!: DataExchangeAgreement
  exchange!: DataExchange
  jwkPairOrig: JwkPair
  publicJwkDest: JWK
  block: OrigBlock
  dltAgent!: NrpDltAgentOrig
  readonly initialized: Promise<boolean>

  /**
   * @param agreement - a DataExchangeAgreement
   * @param privateJwk - the private key that will be used to sign the proofs
   * @param block - the block of data to transmit in this data exchange
   * @param dltAgent - a DLT agent providing read-write connection to NRP smart contract
   */
  constructor (agreement: DataExchangeAgreement, privateJwk: JWK, block: Uint8Array, dltAgent: NrpDltAgentOrig) {
    this.jwkPairOrig = {
      privateJwk: privateJwk,
      publicJwk: JSON.parse(agreement.orig) as JWK
    }
    this.publicJwkDest = JSON.parse(agreement.dest) as JWK

    // @ts-expect-error I will end assigning the complete Block in the async init()
    this.block = {
      raw: block
    }

    this.initialized = new Promise((resolve, reject) => {
      this.init(agreement, dltAgent).then(() => {
        resolve(true)
      }).catch((error) => {
        reject(error)
      })
    })
  }

  private async init (agreement: DataExchangeAgreement, dltAgent: NrpDltAgentOrig): Promise<void> {
    this.agreement = await parseAgreement(agreement)

    await verifyKeyPair(this.jwkPairOrig.publicJwk, this.jwkPairOrig.privateJwk)

    const secret = await oneTimeSecret(this.agreement.encAlg)
    this.block = {
      ...this.block,
      secret,
      jwe: await jweEncrypt(this.block.raw, secret.jwk, this.agreement.encAlg)
    }
    const cipherblockDgst = b64.encode(await sha(this.block.jwe, this.agreement.hashAlg), true, false)
    const blockCommitment = b64.encode(await sha(this.block.raw, this.agreement.hashAlg), true, false)
    const secretCommitment = b64.encode(await sha(new Uint8Array(hexToBuf(this.block.secret.hex)), this.agreement.hashAlg), true, false)

    const dataExchangePreview: Omit<DataExchange, 'id'> = {
      ...this.agreement,
      cipherblockDgst,
      blockCommitment,
      secretCommitment
    }

    const id = await exchangeId(dataExchangePreview)

    this.exchange = {
      ...dataExchangePreview,
      id
    }

    await this._dltSetup(dltAgent)
  }

  private async _dltSetup (dltAgent: NrpDltAgentOrig): Promise<void> {
    this.dltAgent = dltAgent

    const signerAddress: string = parseHex(await this.dltAgent.getAddress(), true)

    if (signerAddress !== this.exchange.ledgerSignerAddress) {
      throw new Error(`ledgerSignerAddress: ${this.exchange.ledgerSignerAddress} does not meet the address ${signerAddress} derived from the provided private key`)
    }

    const contractAddress = parseHex(await this.dltAgent.getContractAddress(), true)

    if (contractAddress !== parseHex(this.agreement.ledgerContractAddress, true)) {
      throw new Error(`Contract address in use ${contractAddress} does not meet the agreed one ${this.agreement.ledgerContractAddress}`)
    }
  }

  /**
   * Creates the proof of origin (PoO).
   * Besides returning its value, it is also stored in this.block.poo
   *
   * @returns a compact JWS with the PoO along with its decoded payload
   */
  async generatePoO (): Promise<StoredProof<PoOPayload>> {
    await this.initialized

    this.block.poo = await createProof<PoOPayload>({
      proofType: 'PoO',
      iss: 'orig',
      exchange: this.exchange
    }, this.jwkPairOrig.privateJwk)
    return this.block.poo
  }

  /**
   * Verifies a proof of reception.
   * If verification passes, `por` is added to `this.block`
   *
   * @param por - A PoR in caompact JWS format
   * @param options - time-related verifications
   * @returns the verified payload and protected header
   */
  async verifyPoR (por: string, options?: Pick<TimestampVerifyOptions, 'timestamp' | 'tolerance'>): Promise<StoredProof<PoRPayload>> {
    await this.initialized

    if (this.block.poo === undefined) {
      throw new Error('Cannot verify a PoR if not even a PoO have been created')
    }

    const expectedPayloadClaims: Omit<PoRPayload, 'iat'> = {
      proofType: 'PoR',
      iss: 'dest',
      exchange: this.exchange,
      poo: this.block.poo.jws
    }

    const pooTs = this.block.poo.payload.iat * 1000
    const opts: TimestampVerifyOptions = {
      timestamp: Date.now(),
      notBefore: pooTs,
      notAfter: pooTs + this.exchange.pooToPorDelay,
      ...options
    }
    const verified = await verifyProof<PoRPayload>(por, expectedPayloadClaims, opts)

    this.block.por = {
      jws: por,
      payload: verified.payload
    }

    return this.block.por
  }

  /**
   * Creates the proof of publication (PoP).
   * Besides returning its value, it is also stored in `this.block.pop`
   *
   * @returns a compact JWS with the PoP
   */
  async generatePoP (): Promise<StoredProof<PoPPayload>> {
    await this.initialized

    if (this.block.por === undefined) {
      throw new Error('Before computing a PoP, you have first to have received and verified the PoR')
    }

    const verificationCode = await this.dltAgent.deploySecret(this.block.secret.hex, this.exchange.id)

    const payload: Omit<PoPPayload, 'iat'> = {
      proofType: 'PoP',
      iss: 'orig',
      exchange: this.exchange,
      por: this.block.por.jws,
      secret: JSON.stringify(this.block.secret.jwk),
      verificationCode
    }
    this.block.pop = await createProof(payload, this.jwkPairOrig.privateJwk)
    return this.block.pop
  }

  /**
   * Generates a verification request that can be used to query the
   * Conflict-Resolver Service for completeness of the non-repudiation protocol
   *
   * @returns the verification request as a compact JWS signed with 'orig's private key
   */
  async generateVerificationRequest (): Promise<string> {
    await this.initialized

    if (this.block.por === undefined) {
      throw new Error('Before generating a VerificationRequest, you have first to hold a valid PoR for the exchange')
    }

    return await generateVerificationRequest('orig', this.exchange.id, this.block.por.jws, this.jwkPairOrig.privateJwk)
  }
}
