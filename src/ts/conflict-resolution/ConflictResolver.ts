import { importJWK, JWTPayload, SignJWT } from 'jose'
import { jwsDecode, verifyKeyPair } from '../crypto'
import { EthersWalletAgentDest, WalletAgentDest } from '../dlt/wallet-agents'
import { NrError } from '../errors'
import { DisputeRequestPayload, DisputeResolutionPayload, JwkPair, PoRPayload, ResolutionPayload, VerificationRequestPayload, VerificationResolutionPayload } from '../types'
import { parseJwk } from '../utils'
import { checkCompleteness } from './checkCompleteness'
import { checkDecryption } from './checkDecryption'

/**
 * The base class that should be instantiated in order to create a Conflict Resolver instance.
 * The Conflict Resolver is an external entity that can:
 *  1. verify the completeness of a data exchange that used the non-repudiation protocol;
 *  2. resolve a dispute when a consumer states that she/he cannot decrypt the data received
 */
export class ConflictResolver {
  jwkPair: JwkPair
  wallet: WalletAgentDest
  private readonly initialized: Promise<boolean>

  /**
   *
   * @param jwkPair a pair of public/private keys in JWK format
   * @param walletAgent a wallet agent providing read-only access to the non-repudiation protocol smart contract
   */
  constructor (jwkPair: JwkPair, walletAgent?: WalletAgentDest) {
    this.jwkPair = jwkPair

    if (walletAgent !== undefined) {
      this.wallet = walletAgent
    } else {
      this.wallet = new EthersWalletAgentDest()
    }

    this.initialized = new Promise((resolve, reject) => {
      this.init().then(() => {
        resolve(true)
      }).catch((error) => {
        reject(error)
      })
    })
  }

  /**
   * Initialize this instance.
   */
  private async init (): Promise<void> {
    await verifyKeyPair(this.jwkPair.publicJwk, this.jwkPair.privateJwk)
  }

  /**
   * Checks if a give data exchange has completed succesfully
   *
   * @param verificationRequest
   * @returns a signed resolution
   */
  async resolveCompleteness (verificationRequest: string): Promise<string> {
    await this.initialized

    const { payload: vrPayload } = await jwsDecode<VerificationRequestPayload>(verificationRequest)

    let porPayload: PoRPayload
    try {
      const decoded = await jwsDecode<PoRPayload>(vrPayload.por)
      porPayload = decoded.payload
    } catch (error) {
      throw new NrError(error, ['invalid por'])
    }

    const verificationResolution: VerificationResolutionPayload = {
      ...await this._resolution(vrPayload.dataExchangeId, porPayload.exchange[vrPayload.iss]),
      resolution: 'not completed',
      type: 'verification'
    }

    try {
      await checkCompleteness(verificationRequest, this.wallet)
      verificationResolution.resolution = 'completed'
    } catch (error) {
      if (!(error instanceof NrError) ||
      error.nrErrors.includes('invalid verification request') || error.nrErrors.includes('unexpected error')) {
        throw error
      }
    }

    const privateKey = await importJWK(this.jwkPair.privateJwk)

    return await new SignJWT(verificationResolution as unknown as JWTPayload)
      .setProtectedHeader({ alg: this.jwkPair.privateJwk.alg })
      .setIssuedAt(verificationResolution.iat)
      .sign(privateKey)
  }

  /**
   * Checks if the cipherblock provided in a data exchange can be decrypted
   * with the published secret.
   *
   * @todo Check also data schema
   *
   * @param disputeRequest
   * @returns a signed resolution
   */
  async resolveDispute (disputeRequest: string): Promise<string> {
    await this.initialized

    const { payload: drPayload } = await jwsDecode<DisputeRequestPayload>(disputeRequest)

    let porPayload: PoRPayload
    try {
      const decoded = await jwsDecode<PoRPayload>(drPayload.por)
      porPayload = decoded.payload
    } catch (error) {
      throw new NrError(error, ['invalid por'])
    }

    const disputeResolution: DisputeResolutionPayload = {
      ...await this._resolution(drPayload.dataExchangeId, porPayload.exchange[drPayload.iss]),
      resolution: 'denied',
      type: 'dispute'
    }

    try {
      await checkDecryption(disputeRequest, this.wallet)
    } catch (error) {
      if (error instanceof NrError && error.nrErrors.includes('decryption failed')) {
        disputeResolution.resolution = 'accepted'
      } else {
        throw new NrError(error, ['cannot verify'])
      }
    }

    const privateKey = await importJWK(this.jwkPair.privateJwk)

    return await new SignJWT(disputeResolution as unknown as JWTPayload)
      .setProtectedHeader({ alg: this.jwkPair.privateJwk.alg })
      .setIssuedAt(disputeResolution.iat)
      .sign(privateKey)
  }

  private async _resolution (dataExchangeId: string, sub: string): Promise<ResolutionPayload> {
    return {
      proofType: 'resolution',
      dataExchangeId,
      iat: Math.floor(Date.now() / 1000),
      iss: await parseJwk(this.jwkPair.publicJwk, true),
      sub
    }
  }
}
