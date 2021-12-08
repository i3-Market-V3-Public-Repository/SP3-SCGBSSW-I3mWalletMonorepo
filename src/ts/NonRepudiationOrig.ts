import * as b64 from '@juanelas/base64'
import { hexToBuf } from 'bigint-conversion'
import { ethers } from 'ethers'
import { hashable } from 'object-sha'
import { } from '.'
import { createProof } from './createProof'
import { defaultDltConfig } from './defaultDltConfig'
import { jweEncrypt } from './jwe'
import { oneTimeSecret } from './oneTimeSecret'
import { sha } from './sha'
import { DataExchange, DataExchangeAgreement, DltConfig, JWK, JwkPair, OrigBlock, PoOInputPayload, PoPInputPayload, PoRInputPayload, ProofPayload, StoredProof, TimestampVerifyOptions } from './types'
import { verifyKeyPair } from './verifyKeyPair'
import { verifyProof } from './verifyProof'
import { parseHex } from './utils'

/**
 * The base class that should be instantiated by the origin of a data
 * exchange when non-repudiation is required. In the i3-MARKET ecosystem it is
 * likely to be a Provider.
 */
export class NonRepudiationOrig {
  agreement: DataExchangeAgreement
  exchange!: DataExchange
  jwkPairOrig: JwkPair
  publicJwkDest: JWK
  block: OrigBlock
  dltConfig: DltConfig
  dltContract!: ethers.Contract
  initialized: Promise<boolean>

  /**
   * @param agreement - a DataExchangeAgreement
   * @param privateJwk - the private key that will be used to sign the proofs
   * @param block - the block of data to transmit in this data exchange
   * @param dltConfig - an object with the necessary configuration for the (Ethereum-like) DLT
   * @param privateLedgerKeyHex - the private key (d parameter) as a hexadecimal string used to sign transactions to the ledger. If not provided, it is assumed that is the same as privateJwk
   */
  constructor (agreement: DataExchangeAgreement, privateJwk: JWK, block: Uint8Array, dltConfig?: Partial<DltConfig>, privateLedgerKeyHex?: string) {
    this.jwkPairOrig = {
      privateJwk: privateJwk,
      publicJwk: JSON.parse(agreement.orig) as JWK
    }
    this.publicJwkDest = JSON.parse(agreement.dest) as JWK

    this.agreement = {
      ...agreement,
      ledgerContractAddress: parseHex(agreement.ledgerContractAddress),
      ledgerSignerAddress: parseHex(agreement.ledgerSignerAddress)
    }

    // @ts-expect-error I will end assigning the complete Block in the async init()
    this.block = {
      raw: block
    }

    this.dltConfig = {
      ...defaultDltConfig,
      ...dltConfig
    }

    const privDltKeyHex = (privateLedgerKeyHex !== undefined) ? parseHex(privateLedgerKeyHex) : undefined
    this.initialized = new Promise((resolve, reject) => {
      this.init(privDltKeyHex).then(() => {
        resolve(true)
      }).catch((error) => {
        reject(error)
      })
    })
  }

  /**
   * Initialize this instance. It MUST be invoked before calling any other method.
   */
  async init (privateLedgerKeyHex?: string): Promise<void> {
    await verifyKeyPair(this.jwkPairOrig.publicJwk, this.jwkPairOrig.privateJwk)

    const secret = await oneTimeSecret(this.agreement.encAlg)
    this.block = {
      ...this.block,
      secret,
      jwe: await jweEncrypt(this.block.raw, secret.jwk, this.agreement.encAlg)
    }
    const cipherblockDgst = await sha(this.block.jwe, this.agreement.hashAlg)

    const id = await sha(hashable({ ...this.agreement, cipherblockDgst }), 'SHA-256')

    this.exchange = {
      ...this.agreement,
      id,
      cipherblockDgst,
      blockCommitment: await sha(this.block.raw, this.agreement.hashAlg),
      secretCommitment: await sha(new Uint8Array(hexToBuf(this.block.secret.hex)), this.agreement.hashAlg)
    }

    await this._dltSetup(privateLedgerKeyHex)
  }

  private async _dltSetup (privateLedgerKeyHex?: string): Promise<void> {
    if (!this.dltConfig.disable) {
      const rpcProvider = new ethers.providers.JsonRpcProvider(this.dltConfig.rpcProviderUrl)
      if (this.jwkPairOrig.privateJwk.d === undefined) {
        throw new Error('INVALID SIGNING ALGORITHM: No d property found on private key')
      }
      const privateKey: Uint8Array = (privateLedgerKeyHex !== undefined)
        ? new Uint8Array(hexToBuf(privateLedgerKeyHex))
        : b64.decode(this.jwkPairOrig.privateJwk.d) as Uint8Array
      const signingKey = new ethers.utils.SigningKey(privateKey)
      const signer = new ethers.Wallet(signingKey, rpcProvider)
      const signerAddress: string = parseHex(await signer.getAddress())

      if (signerAddress !== this.exchange.ledgerSignerAddress) {
        throw new Error(`ledgerSignerAddress: ${this.exchange.ledgerSignerAddress} does not meet the address associated to the provided private key ${signerAddress}`)
      }

      if (this.agreement.ledgerContractAddress !== parseHex(this.dltConfig.contract.address)) {
        throw new Error(`Contract address ${parseHex(this.dltConfig.contract.address)} does not meet agreed one ${this.agreement.ledgerContractAddress}`)
      }

      this.dltContract = new ethers.Contract(this.agreement.ledgerContractAddress, this.dltConfig.contract.abi, signer)
    }
  }

  /**
   * Creates the proof of origin (PoO).
   * Besides returning its value, it is also stored in this.block.poo
   *
   * @returns a compact JWS with the PoO along with its decoded payload
   */
  async generatePoO (): Promise<StoredProof> {
    await this.initialized

    const payload: PoOInputPayload = {
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
   * @param clockToleranceMs - expected clock tolerance in milliseconds when comparing Dates
   * @param currentDate - check the proof as it were checked in this date
   * @returns the verified payload and protected header
   */
  async verifyPoR (por: string, clockToleranceMs?: number, currentDate?: Date): Promise<StoredProof> {
    await this.initialized

    if (this.block?.poo === undefined) {
      throw new Error('Cannot verify a PoR if not even a PoO have been created')
    }

    const expectedPayloadClaims: PoRInputPayload = {
      proofType: 'PoR',
      iss: 'dest',
      exchange: this.exchange,
      poo: this.block.poo.jws
    }

    const proofVerifyOptions: TimestampVerifyOptions = {
      expectedTimestampInterval: {
        min: this.block.poo?.payload.iat * 1000,
        max: this.block.poo?.payload.iat * 1000 + this.exchange.pooToPopDelay
      }
    }
    if (clockToleranceMs !== undefined) proofVerifyOptions.clockToleranceMs = clockToleranceMs
    if (currentDate !== undefined) proofVerifyOptions.currentTimestamp = currentDate.valueOf()

    const verified = await verifyProof(por, this.publicJwkDest, expectedPayloadClaims, proofVerifyOptions)

    this.block.por = {
      jws: por,
      payload: verified.payload as ProofPayload
    }

    return this.block.por
  }

  /**
   * Creates the proof of publication (PoP).
   * Besides returning its value, it is also stored in `this.block.pop`
   *
   * @returns a compact JWS with the PoP
   */
  async generatePoP (): Promise<StoredProof> {
    await this.initialized

    if (this.block.por === undefined) {
      throw new Error('Before computing a PoP, you have first to have received and verified the PoR')
    }

    let verificationCode = 'verificationCode'
    if (!this.dltConfig.disable) {
      const secret = ethers.BigNumber.from(`0x${this.block.secret.hex}`)

      // TO-DO: it fails with a random account since it hasn't got any funds (ethers). Do we have a faucet? Set gas prize to 0?
      const setRegistryTx = await this.dltContract.setRegistry(`0x${this.exchange.id}`, secret, { gasLimit: this.dltConfig.gasLimit })
      verificationCode = setRegistryTx.hash

      // TO-DO: I would say that we can remove the next wait
      // await setRegistryTx.wait()
    }

    const payload: PoPInputPayload = {
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
}
