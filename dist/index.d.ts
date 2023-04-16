/// <reference types="node" />
import { ContractInterface } from '@ethersproject/contracts';
export { ContractInterface } from '@ethersproject/contracts';
import { JWK as JWK$1, JWTHeaderParameters, JWEHeaderParameters, KeyLike as KeyLike$1, CompactDecryptResult } from 'jose';
export { KeyLike } from 'jose';
import { ethers } from 'ethers';
import { EventEmitter as EventEmitter$1 } from 'events';
import { KeyObject } from 'crypto';

declare const HASH_ALGS: readonly ["SHA-256", "SHA-384", "SHA-512"];
declare const SIGNING_ALGS: readonly ["ES256", "ES384", "ES512"];
declare const ENC_ALGS: readonly ["A128GCM", "A256GCM"];
declare const KEY_AGREEMENT_ALGS: readonly ["ECDH-ES"];

/* eslint-disable @typescript-eslint/no-empty-interface */
declare namespace WalletComponents {
  export namespace Schemas {
    /**
         * Error
         */
    export interface ApiError {
      code: number // int32
      message: string
    }
    /**
         * CompactJWS
         */
    export type CompactJWS = string // ^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$
    /**
         * Contract
         */
    export interface Contract {
      /**
             * example:
             * Contract
             */
      type: 'Contract'
      /**
             * example:
             * Resource name
             */
      name?: string
      identity?: /**
             * a DID using the ethr resolver
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      Did /* ^did:ethr:(\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$ */
      resource: {
        dataSharingAgreement: DataSharingAgreement
        keyPair?: JwkPair
      }
    }
    export interface DataExchange {
      /**
             * A stringified JWK with alphabetically sorted claims
             * example:
             * {"alg":"ES256","crv":"P-256","kty":"EC","x":"t0ueMqN9j8lWYa2FXZjSw3cycpwSgxjl26qlV6zkFEo","y":"rMqWC9jGfXXLEh_1cku4-f0PfbFa1igbNWLPzos_gb0"}
             */
      orig: string
      /**
             * A stringified JWK with alphabetically sorted claims
             * example:
             * {"alg":"ES256","crv":"P-256","kty":"EC","x":"sI5lkRCGpfeViQzAnu-gLnZnIGdbtfPiY7dGk4yVn-k","y":"4iFXDnEzPEb7Ce_18RSV22jW6VaVCpwH3FgTAKj3Cf4"}
             */
      dest: string
      /**
             * example:
             * A256GCM
             */
      encAlg: 'A128GCM' | 'A256GCM'
      /**
             * example:
             * ES256
             */
      signingAlg: 'ES256' | 'ES384' | 'ES512'
      /**
             * example:
             * SHA-256
             */
      hashAlg: 'SHA-256' | 'SHA-384' | 'SHA-512'
      ledgerContractAddress: /**
             * Ethereum Address in EIP-55 format (with checksum)
             * example:
             * 0x71C7656EC7ab88b098defB751B7401B5f6d8976F
             */
      EthereumAddress /* ^0x([0-9A-Fa-f]){40}$ */
      ledgerSignerAddress: /**
             * Ethereum Address in EIP-55 format (with checksum)
             * example:
             * 0x71C7656EC7ab88b098defB751B7401B5f6d8976F
             */
      EthereumAddress /* ^0x([0-9A-Fa-f]){40}$ */
      /**
             * Maximum acceptable time in milliseconds between issued PoO and verified PoR
             * example:
             * 10000
             */
      pooToPorDelay: number
      /**
             * Maximum acceptable time in milliseconds between issued PoO and issued PoP
             * example:
             * 20000
             */
      pooToPopDelay: number
      /**
             * Maximum acceptable time between issued PoO and secret published on the ledger
             * example:
             * 180000
             */
      pooToSecretDelay: number
      /**
             * A stringified JSON-LD schema describing the data format
             */
      schema?: string
      /**
             * hash of the cipherblock in base64url with no padding
             */
      cipherblockDgst: string // ^[a-zA-Z0-9_-]+$
      /**
             * hash of the plaintext block in base64url with no padding
             */
      blockCommitment: string // ^[a-zA-Z0-9_-]+$
      /**
             * ash of the secret that can be used to decrypt the block in base64url with no padding
             */
      secretCommitment: string // ^[a-zA-Z0-9_-]+$
    }
    export interface DataExchangeAgreement {
      /**
             * A stringified JWK with alphabetically sorted claims
             * example:
             * {"alg":"ES256","crv":"P-256","kty":"EC","x":"t0ueMqN9j8lWYa2FXZjSw3cycpwSgxjl26qlV6zkFEo","y":"rMqWC9jGfXXLEh_1cku4-f0PfbFa1igbNWLPzos_gb0"}
             */
      orig: string
      /**
             * A stringified JWK with alphabetically sorted claims
             * example:
             * {"alg":"ES256","crv":"P-256","kty":"EC","x":"sI5lkRCGpfeViQzAnu-gLnZnIGdbtfPiY7dGk4yVn-k","y":"4iFXDnEzPEb7Ce_18RSV22jW6VaVCpwH3FgTAKj3Cf4"}
             */
      dest: string
      /**
             * example:
             * A256GCM
             */
      encAlg: 'A128GCM' | 'A256GCM'
      /**
             * example:
             * ES256
             */
      signingAlg: 'ES256' | 'ES384' | 'ES512'
      /**
             * example:
             * SHA-256
             */
      hashAlg: 'SHA-256' | 'SHA-384' | 'SHA-512'
      ledgerContractAddress: /**
             * Ethereum Address in EIP-55 format (with checksum)
             * example:
             * 0x71C7656EC7ab88b098defB751B7401B5f6d8976F
             */
      EthereumAddress /* ^0x([0-9A-Fa-f]){40}$ */
      ledgerSignerAddress: /**
             * Ethereum Address in EIP-55 format (with checksum)
             * example:
             * 0x71C7656EC7ab88b098defB751B7401B5f6d8976F
             */
      EthereumAddress /* ^0x([0-9A-Fa-f]){40}$ */
      /**
             * Maximum acceptable time in milliseconds between issued PoO and verified PoR
             * example:
             * 10000
             */
      pooToPorDelay: number
      /**
             * Maximum acceptable time in milliseconds between issued PoO and issued PoP
             * example:
             * 20000
             */
      pooToPopDelay: number
      /**
             * Maximum acceptable time between issued PoO and secret published on the ledger
             * example:
             * 180000
             */
      pooToSecretDelay: number
      /**
             * A stringified JSON-LD schema describing the data format
             */
      schema?: string
    }
    /**
         * DataExchangeResource
         */
    export interface DataExchangeResource {
      /**
             * example:
             * DataExchange
             */
      type: 'DataExchange'
      /**
             * example:
             * Resource name
             */
      name?: string
      resource: DataExchange
    }
    export interface DataSharingAgreement {
      dataOfferingDescription: {
        dataOfferingId: string
        version: number
        category?: string
        active: boolean
        title?: string
      }
      parties: {
        providerDid: /**
                 * a DID using the ethr resolver
                 * example:
                 * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                 */
        Did /* ^did:ethr:(\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$ */
        consumerDid: /**
                 * a DID using the ethr resolver
                 * example:
                 * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                 */
        Did /* ^did:ethr:(\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$ */
      }
      purpose: string
      duration: {
        creationDate: number
        startDate: number
        endDate: number
      }
      intendedUse: {
        processData: boolean
        shareDataWithThirdParty: boolean
        editData: boolean
      }
      licenseGrant: {
        transferable: boolean
        exclusiveness: boolean
        paidUp: boolean
        revocable: boolean
        processing: boolean
        modifying: boolean
        analyzing: boolean
        storingData: boolean
        storingCopy: boolean
        reproducing: boolean
        distributing: boolean
        loaning: boolean
        selling: boolean
        renting: boolean
        furtherLicensing: boolean
        leasing: boolean
      }
      dataStream: boolean
      personalData: boolean
      pricingModel: {
        paymentType?: string
        pricingModelName?: string
        basicPrice: number // float
        currency: string
        fee?: number // float
        hasPaymentOnSubscription?: {
          paymentOnSubscriptionName?: string
          paymentType?: string
          timeDuration?: string
          description?: string
          repeat?: string
          hasSubscriptionPrice?: number
        }
        hasFreePrice: {
          hasPriceFree?: boolean
        }
      }
      dataExchangeAgreement: DataExchangeAgreement
      signatures: {
        providerSignature: /* CompactJWS */ CompactJWS /* ^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$ */
        consumerSignature: /* CompactJWS */ CompactJWS /* ^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$ */
      }
    }
    /**
         * JwtPayload
         */
    export interface DecodedJwt {
      header?: {
        [name: string]: any
        typ: 'JWT'
        alg: 'ES256K'
      }
      payload?: {
        [name: string]: any
        iss: /**
                 * a DID using the ethr resolver
                 * example:
                 * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                 */
        Did /* ^did:ethr:(\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$ */
      }
      signature: string // ^[A-Za-z0-9_-]+$
      /**
             * <base64url(header)>.<base64url(payload)>
             */
      data: string // ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$
    }
    /**
         * a DID using the ethr resolver
         * example:
         * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
         */
    export type Did = string // ^did:ethr:(\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$
    /**
         * Ethereum Address in EIP-55 format (with checksum)
         * example:
         * 0x71C7656EC7ab88b098defB751B7401B5f6d8976F
         */
    export type EthereumAddress = string // ^0x([0-9A-Fa-f]){40}$
    /**
         * IdentityCreateInput
         * Besides the here defined options, provider specific properties should be added here if necessary, e.g. "path" for BIP21 wallets, or the key algorithm (if the wallet supports multiple algorithm).
         *
         */
    export interface IdentityCreateInput {
      [name: string]: any
      alias?: string
    }
    /**
         * IdentityCreateOutput
         * It returns the account id and type
         *
         */
    export interface IdentityCreateOutput {
      [name: string]: any
      did: /**
             * a DID using the ethr resolver
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      Did /* ^did:ethr:(\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$ */
    }
    /**
         * Identity Data
         */
    export interface IdentityData {
      /**
             * example:
             * did:ethr:i3m:0x03142f480f831e835822fc0cd35726844a7069d28df58fb82037f1598812e1ade8
             */
      did: string
      /**
             * example:
             * identity1
             */
      alias?: string
      /**
             * example:
             * did:ethr:i3m
             */
      provider?: string
      /**
             * example:
             * [
             *   "0x8646cAcF516de1292be1D30AB68E7Ea51e9B1BE7"
             * ]
             */
      addresses?: /**
             * Ethereum Address in EIP-55 format (with checksum)
             * example:
             * 0x71C7656EC7ab88b098defB751B7401B5f6d8976F
             */
      EthereumAddress /* ^0x([0-9A-Fa-f]){40}$ */[]
    }
    /**
         * IdentityListInput
         * A list of DIDs
         */
    export type IdentityListInput = Array<{
      did: /**
             * a DID using the ethr resolver
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      Did /* ^did:ethr:(\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$ */
    }>
    /**
         * IdentitySelectOutput
         */
    export interface IdentitySelectOutput {
      did: /**
             * a DID using the ethr resolver
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      Did /* ^did:ethr:(\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$ */
    }
    export interface JwkPair {
      /**
             * A stringified JWK with alphabetically sorted claims that represents a private key (complementary to `publicJwk`)
             *
             * example:
             * {"alg":"ES256","crv":"P-256","d":"rQp_3eZzvXwt1sK7WWsRhVYipqNGblzYDKKaYirlqs0","kty":"EC","x":"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8","y":"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE"}
             */
      privateJwk: string
      /**
             * A stringified JWK with alphabetically sorted claims that represents the public key (complementary to `privateJwk`).
             *
             * example:
             * {"alg":"ES256","crv":"P-256","kty":"EC","x":"sMGSjfIlRJRseMpx3iHhCx4uh-6N4-AUKX18lmoeSD8","y":"Hu8EcpyH2XrCd-oKqm9keEhnMx2v2QaPs6P4Vs8OkpE"}
             */
      publicJwk: string
    }
    /**
         * JWK pair
         */
    export interface KeyPair {
      /**
             * example:
             * KeyPair
             */
      type: 'KeyPair'
      /**
             * example:
             * Resource name
             */
      name?: string
      identity?: /**
             * a DID using the ethr resolver
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      Did /* ^did:ethr:(\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$ */
      resource: {
        keyPair: JwkPair
      }
    }
    /**
         * NonRepudiationProof
         */
    export interface NonRepudiationProof {
      /**
             * example:
             * NonRepudiationProof
             */
      type: 'NonRepudiationProof'
      /**
             * example:
             * Resource name
             */
      name?: string
      /**
             * a non-repudiation proof (either a PoO, a PoR or a PoP) as a compact JWS
             */
      resource: any
    }
    /**
         * ObjectResource
         */
    export interface ObjectResource {
      /**
             * example:
             * Object
             */
      type: 'Object'
      /**
             * example:
             * Resource name
             */
      name?: string
      parentResource?: string
      identity?: /**
             * a DID using the ethr resolver
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      Did /* ^did:ethr:(\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$ */
      resource: {
        [name: string]: any
      }
    }
    /**
         * ProviderData
         * A JSON object with information of the DLT provider currently in use.
         */
    export interface ProviderData {
      [name: string]: any
      /**
             * example:
             * did:ethr:i3m
             */
      provider?: string
      /**
             * example:
             * i3m
             */
      network?: string
      rpcUrl?: string | string[]
    }
    /**
         * Receipt
         */
    export interface Receipt {
      receipt: string
    }
    /**
         * Resource
         */
    export type Resource = /* Resource */ /* VerifiableCredential */ VerifiableCredential | /* ObjectResource */ ObjectResource | /* JWK pair */ KeyPair | /* Contract */ Contract | /* NonRepudiationProof */ NonRepudiationProof | /* DataExchangeResource */ DataExchangeResource
    export interface ResourceId {
      id: string
    }
    /**
         * ResourceListOutput
         * A list of resources
         */
    export type ResourceListOutput = /* Resource */ Resource[]
    export type ResourceType = 'VerifiableCredential' | 'Object' | 'KeyPair' | 'Contract' | 'DataExchange' | 'NonRepudiationProof'
    /**
         * SignInput
         */
    export type SignInput = /* SignInput */ /* SignTransaction */ SignTransaction | /* SignRaw */ SignRaw | /* SignJWT */ SignJWT
    /**
         * SignJWT
         */
    export interface SignJWT {
      type: 'JWT'
      data: {
        /**
                 * header fields to be added to the JWS header. "alg" and "kid" will be ignored since they are automatically added by the wallet.
                 */
        header?: {
          [name: string]: any
        }
        /**
                 * A JSON object to be signed by the wallet. It will become the payload of the generated JWS. 'iss' (issuer) and 'iat' (issued at) will be automatically added by the wallet and will override provided values.
                 */
        payload: {
          [name: string]: any
        }
      }
    }
    /**
         * SignOutput
         */
    export interface SignOutput {
      signature: string
    }
    /**
         * SignRaw
         */
    export interface SignRaw {
      type: 'Raw'
      data: {
        /**
                 * Base64Url encoded data to sign
                 */
        payload: string // ^[A-Za-z0-9_-]+$
      }
    }
    /**
         * SignTransaction
         */
    export interface SignTransaction {
      type: 'Transaction'
      data: /* Transaction */ Transaction
    }
    /**
         * SignTypes
         */
    export type SignTypes = 'Transaction' | 'Raw' | 'JWT'
    /**
         * SignedTransaction
         * A list of resources
         */
    export interface SignedTransaction {
      transaction?: string // ^0x(?:[A-Fa-f0-9])+$
    }
    /**
         * Transaction
         */
    export interface Transaction {
      [name: string]: any
      from?: string
      to?: string
      nonce?: number
    }
    /**
         * VerifiableCredential
         */
    export interface VerifiableCredential {
      /**
             * example:
             * VerifiableCredential
             */
      type: 'VerifiableCredential'
      /**
             * example:
             * Resource name
             */
      name?: string
      resource: {
        [name: string]: any
        /**
                 * example:
                 * [
                 *   "https://www.w3.org/2018/credentials/v1"
                 * ]
                 */
        '@context': string[]
        /**
                 * example:
                 * http://example.edu/credentials/1872
                 */
        id?: string
        /**
                 * example:
                 * [
                 *   "VerifiableCredential"
                 * ]
                 */
        type: string[]
        issuer: {
          [name: string]: any
          id: /**
                     * a DID using the ethr resolver
                     * example:
                     * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                     */
          Did /* ^did:ethr:(\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$ */
        }
        /**
                 * example:
                 * 2021-06-10T19:07:28.000Z
                 */
        issuanceDate: string // date-time
        credentialSubject: {
          [name: string]: any
          id: /**
                     * a DID using the ethr resolver
                     * example:
                     * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                     */
          Did /* ^did:ethr:(\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$ */
        }
        proof: {
          [name: string]: any
          type: 'JwtProof2020'
        }
      }
    }
    /**
         * VerificationOutput
         */
    export interface VerificationOutput {
      /**
             * whether verification has been successful or has failed
             */
      verification: 'success' | 'failed'
      /**
             * error message if verification failed
             */
      error?: string
      /**
             * the decoded JWT
             */
      decodedJwt?: any
    }
  }
}
declare namespace WalletPaths {
  export namespace DidJwtVerify {
    export interface RequestBody {
      /**
             * example:
             * eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJmaWVsZDEiOiJzYWRzYWQ3NSIsImZpZWxkMiI6ImFmZnNhczlmODdzIiwiaXNzIjoiZGlkOmV0aHI6aTNtOjB4MDNmOTcwNjRhMzUzZmFmNWRkNTQwYWE2N2I2OTE2YmY1NmMwOWM1MGNjODAzN2E0NTNlNzg1ODdmMjdmYjg4ZTk0IiwiaWF0IjoxNjY1NDAwMzYzfQ.IpQ7WprvDMk6QWcJXuPBazat-2657dWIK-iGvOOB5oAhAmMqDBm8OEtKordqeqcEWwhWw_C7_ziMMZkPz1JIkw
             */
      jwt: string // ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$
      /**
             * The expected values of the proof's payload claims. An expected value of '' can be used to just check that the claim is in the payload. An example could be:
             *
             * ```json
             * {
             *   iss: 'orig',
             *   exchange: {
             *     id: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',
             *     orig: '{"kty":"EC","x":"rPMP39e-o8cU6m4WL8_qd2wxo-nBTjWXZtPGBiiGCTY","y":"0uvxGEebFDxKOHYUlHREzq4mRULuZvQ6LB2I11yE1E0","crv":"P-256"}', // Public key in JSON.stringify(JWK) of the block origin (sender)
             *     dest: '{"kty":"EC","x":"qf_mNdy57ia1vAq5QLpTPxJUCRhS2003-gL0nLcbXoA","y":"H_8YwSCKJhDbZv17YEgDfAiKTaQ8x0jpLYCC2myxAeY","crv":"P-256"}', // Public key in JSON.stringify(JWK) of the block destination (receiver)
             *     hash_alg: 'SHA-256',
             *     cipherblock_dgst: 'IBUIstf98_afbiuh7UaifkasytNih7as-Jah61ls9UI', // hash of the cipherblock in base64url with no padding
             *     block_commitment: '', // hash of the plaintext block in base64url with no padding
             *     secret_commitment: '' // hash of the secret that can be used to decrypt the block in base64url with no padding
             *   }
             * }
             * ```
             *
             */
      expectedPayloadClaims?: {
        [name: string]: any
      }
    }
    export namespace Responses {
      export type $200 = /* VerificationOutput */ WalletComponents.Schemas.VerificationOutput
      export type Default = /* Error */ WalletComponents.Schemas.ApiError
    }
  }
  export namespace IdentityCreate {
    export type RequestBody = /**
         * IdentityCreateInput
         * Besides the here defined options, provider specific properties should be added here if necessary, e.g. "path" for BIP21 wallets, or the key algorithm (if the wallet supports multiple algorithm).
         *
         */
        WalletComponents.Schemas.IdentityCreateInput
    export namespace Responses {
      export type $201 = /**
             * IdentityCreateOutput
             * It returns the account id and type
             *
             */
            WalletComponents.Schemas.IdentityCreateOutput
      export type Default = /* Error */ WalletComponents.Schemas.ApiError
    }
  }
  export namespace IdentityDeployTransaction {
    export namespace Parameters {
      export type Did = /**
             * a DID using the ethr resolver
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
            WalletComponents.Schemas.Did /* ^did:ethr:(\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$ */
    }
    export interface PathParameters {
      did: Parameters.Did
    }
    export type RequestBody = /* Transaction */ WalletComponents.Schemas.Transaction
    export namespace Responses {
      export type $200 = /* Receipt */ WalletComponents.Schemas.Receipt
      export type Default = /* Error */ WalletComponents.Schemas.ApiError
    }
  }
  export namespace IdentityInfo {
    export namespace Parameters {
      export type Did = /**
             * a DID using the ethr resolver
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
            WalletComponents.Schemas.Did /* ^did:ethr:(\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$ */
    }
    export interface PathParameters {
      did: Parameters.Did
    }
    export namespace Responses {
      export type $200 = /* Identity Data */ WalletComponents.Schemas.IdentityData
      export type Default = /* Error */ WalletComponents.Schemas.ApiError
    }
  }
  export namespace IdentityList {
    export namespace Parameters {
      /**
             * An alias for the identity
             */
      export type Alias = string
    }
    export interface QueryParameters {
      alias?: /* An alias for the identity */ Parameters.Alias
    }
    export namespace Responses {
      export type $200 = /**
             * IdentityListInput
             * A list of DIDs
             */
            WalletComponents.Schemas.IdentityListInput
      export type Default = /* Error */ WalletComponents.Schemas.ApiError
    }
  }
  export namespace IdentitySelect {
    export namespace Parameters {
      /**
             * Message to show to the user with the reason to pick an identity
             */
      export type Reason = string
    }
    export interface QueryParameters {
      reason?: /* Message to show to the user with the reason to pick an identity */ Parameters.Reason
    }
    export namespace Responses {
      export type $200 = /* IdentitySelectOutput */ WalletComponents.Schemas.IdentitySelectOutput
      export type Default = /* Error */ WalletComponents.Schemas.ApiError
    }
  }
  export namespace IdentitySign {
    export namespace Parameters {
      export type Did = /**
             * a DID using the ethr resolver
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
            WalletComponents.Schemas.Did /* ^did:ethr:(\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$ */
    }
    export interface PathParameters {
      did: Parameters.Did
    }
    export type RequestBody = /* SignInput */ WalletComponents.Schemas.SignInput
    export namespace Responses {
      export type $200 = /* SignOutput */ WalletComponents.Schemas.SignOutput
      export type Default = /* Error */ WalletComponents.Schemas.ApiError
    }
  }
  export namespace ProviderinfoGet {
    export namespace Responses {
      export type $200 = /**
             * ProviderData
             * A JSON object with information of the DLT provider currently in use.
             */
            WalletComponents.Schemas.ProviderData
      export type Default = /* Error */ WalletComponents.Schemas.ApiError
    }
  }
  export namespace ResourceCreate {
    export type RequestBody = /* Resource */ WalletComponents.Schemas.Resource
    export namespace Responses {
      export type $201 = WalletComponents.Schemas.ResourceId
      export type Default = /* Error */ WalletComponents.Schemas.ApiError
    }
  }
  export namespace ResourceList {
    export namespace Parameters {
      export type Identity = /**
             * a DID using the ethr resolver
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
            WalletComponents.Schemas.Did /* ^did:ethr:(\w+:)?0x[0-9a-fA-F]{40}([0-9a-fA-F]{26})?$ */
      export type ParentResource = string
      export type Type = WalletComponents.Schemas.ResourceType
    }
    export interface QueryParameters {
      type?: Parameters.Type
      identity?: Parameters.Identity
      parentResource?: Parameters.ParentResource
    }
    export namespace Responses {
      export type $200 = /**
             * ResourceListOutput
             * A list of resources
             */
            WalletComponents.Schemas.ResourceListOutput
      export type Default = /* Error */ WalletComponents.Schemas.ApiError
    }
  }
  export namespace SelectiveDisclosure {
    export namespace Parameters {
      export type Jwt = string // ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$
    }
    export interface PathParameters {
      jwt: Parameters.Jwt /* ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ */
    }
    export namespace Responses {
      export interface $200 {
        jwt?: string
      }
      export type Default = /* Error */ WalletComponents.Schemas.ApiError
    }
  }
  export namespace TransactionDeploy {
    export type RequestBody = /**
         * SignedTransaction
         * A list of resources
         */
        WalletComponents.Schemas.SignedTransaction
    export namespace Responses {
      export interface $200 {
      }
      export type Default = /* Error */ WalletComponents.Schemas.ApiError
    }
  }
}

type HashAlg = typeof HASH_ALGS[number];
type SigningAlg = typeof SIGNING_ALGS[number];
type EncryptionAlg = typeof ENC_ALGS[number];
type Dict<T> = T & {
    [key: string | symbol | number]: any | undefined;
};
interface Algs {
    hashAlg?: HashAlg;
    SigningAlg?: SigningAlg;
    EncAlg?: EncryptionAlg;
}
interface JWK extends JWK$1 {
    alg: SigningAlg | EncryptionAlg;
}
interface ContractConfig {
    address: string;
    abi: ContractInterface;
}
interface DltConfig {
    rpcProviderUrl: string;
    gasLimit: number;
    contract: ContractConfig;
}
interface StoredProof<T extends NrProofPayload> {
    jws: string;
    payload: T;
}
interface Block {
    raw?: Uint8Array;
    jwe?: string;
    secret?: {
        jwk: JWK;
        hex: string;
    };
    poo?: StoredProof<PoOPayload>;
    por?: StoredProof<PoRPayload>;
    pop?: StoredProof<PoPPayload>;
}
interface OrigBlock extends Block {
    raw: Uint8Array;
    jwe: string;
    secret: {
        jwk: JWK;
        hex: string;
    };
}
interface TimestampVerifyOptions {
    timestamp: 'iat' | number;
    notBefore: 'iat' | number;
    notAfter: 'iat' | number;
    tolerance?: number;
}
interface DataSharingAgreement extends WalletComponents.Schemas.DataSharingAgreement {
}
interface DataExchangeAgreement extends WalletComponents.Schemas.DataExchangeAgreement {
}
interface DataExchange extends WalletComponents.Schemas.DataExchange {
    id: string;
}
interface JwkPair {
    publicJwk: JWK;
    privateJwk: JWK;
}
interface ProofPayload {
    iat: number;
    iss: string;
    proofType: string;
}
interface NrProofPayload extends ProofPayload {
    exchange: DataExchange;
}
interface PoOPayload extends NrProofPayload {
    iss: 'orig';
    proofType: 'PoO';
}
interface PoRPayload extends NrProofPayload {
    iss: 'dest';
    proofType: 'PoR';
    poo: string;
}
interface PoPPayload extends NrProofPayload {
    iss: 'orig';
    proofType: 'PoP';
    por: string;
    secret: string;
    verificationCode: string;
}
interface ConflictResolutionRequestPayload extends ProofPayload {
    proofType: 'request';
    iss: 'orig' | 'dest';
    iat: number;
    por: string;
    dataExchangeId: string;
}
interface VerificationRequestPayload extends ConflictResolutionRequestPayload {
    type: 'verificationRequest';
}
interface DisputeRequestPayload extends ConflictResolutionRequestPayload {
    type: 'disputeRequest';
    iss: 'dest';
    cipherblock: string;
}
interface ResolutionPayload extends ProofPayload {
    proofType: 'resolution';
    type?: string;
    resolution?: string;
    dataExchangeId: string;
    iat: number;
    iss: string;
    sub: string;
}
interface VerificationResolutionPayload extends ResolutionPayload {
    type: 'verification';
    resolution: 'completed' | 'not completed';
}
interface DisputeResolutionPayload extends ResolutionPayload {
    type: 'dispute';
    resolution: 'accepted' | 'denied';
}
interface DecodedProof<T extends ProofPayload> {
    header: JWTHeaderParameters;
    payload: T;
    signer?: JWK;
}
type getFromJws<T> = (header: JWEHeaderParameters, payload: T) => Promise<JWK>;
type NrErrorName = 'not a compact jws' | 'invalid key' | 'encryption failed' | 'decryption failed' | 'jws verification failed' | 'invalid algorithm' | 'invalid EIP-55 address' | 'invalid poo' | 'invalid por' | 'invalid pop' | 'invalid dispute request' | 'invalid verification request' | 'invalid dispute request' | 'data exchange not as expected' | 'dataExchange integrity violated' | 'secret not published' | 'secret not published in time' | 'received too late' | 'unexpected error' | 'invalid timestamp' | 'invalid format' | 'cannot contact the ledger' | 'cannot verify';

declare const defaultDltConfig: Omit<DltConfig, 'rpcProviderUrl'>;

declare abstract class NrpDltAgent {
    abstract getContractAddress(): Promise<string>;
}

declare class EthersIoAgent extends NrpDltAgent {
    dltConfig: DltConfig;
    contract: ethers.Contract;
    provider: ethers.providers.Provider;
    initialized: Promise<boolean>;
    constructor(dltConfig: (Partial<DltConfig> & Pick<DltConfig, 'rpcProviderUrl'>) | Promise<(Partial<DltConfig> & Pick<DltConfig, 'rpcProviderUrl'>)>);
    getContractAddress(): Promise<string>;
}

interface NrpDltAgentDest extends NrpDltAgent {
    getSecretFromLedger: (secretLength: number, signerAddress: string, exchangeId: string, timeout: number) => Promise<{
        hex: string;
        iat: number;
    }>;
}

declare class EthersIoAgentDest extends EthersIoAgent implements NrpDltAgentDest {
    getSecretFromLedger(secretLength: number, signerAddress: string, exchangeId: string, timeout: number): Promise<{
        hex: string;
        iat: number;
    }>;
}

//# sourceMappingURL=index.d.ts.map

declare class BaseECDH {
    generateKeys(): Promise<void>;
    getPublicKey(): Promise<string>;
    deriveBits(publicKeyHex: string): Promise<Uint8Array>;
}
type CipherAlgorithms = 'aes-256-gcm';
declare class BaseCipher {
    readonly algorithm: CipherAlgorithms;
    readonly key: Uint8Array;
    constructor(algorithm: CipherAlgorithms, key: Uint8Array);
    encrypt(payload: Uint8Array): Promise<Uint8Array>;
    decrypt(ciphertext: Uint8Array): Promise<Uint8Array>;
}

declare class EventEmitter {
    events: Record<string, Function[]>;
    constructor();
    on(event: string, cb: Function): this;
    emit(event: string, ...data: any): boolean;
}

interface Identity$1 {
    name: string;
    url?: string;
}
interface PKEData {
    id: Identity$1;
    rx: Uint8Array;
    publicKey: string;
}
interface ProtocolPKEData {
    a: PKEData;
    b: PKEData;
    port: number;
    sent: PKEData;
    received: PKEData;
}
interface AuthData {
    cx: Uint8Array;
    nx: Uint8Array;
    r: Uint8Array;
}
interface ProtocolAuthData {
    a: AuthData;
    b: AuthData;
    sent: AuthData;
    received: AuthData;
}

declare class MasterKey {
    readonly port: number;
    readonly from: Identity$1;
    readonly to: Identity$1;
    readonly na: Uint8Array;
    readonly nb: Uint8Array;
    protected secret: Uint8Array;
    protected cipher: BaseCipher;
    protected decipher: BaseCipher;
    constructor(port: number, from: Identity$1, to: Identity$1, na: Uint8Array, nb: Uint8Array, secret: Uint8Array, encryptKey: Uint8Array, decryptKey: Uint8Array);
    encrypt(message: Uint8Array): Promise<Uint8Array>;
    decrypt(ciphertext: Uint8Array): Promise<Uint8Array>;
    toJSON(): any;
    fromHash(): Promise<string>;
    toHash(): Promise<string>;
    static fromSecret(port: number, from: Identity$1, to: Identity$1, na: Uint8Array, nb: Uint8Array, secret: Uint8Array): Promise<MasterKey>;
    static fromJSON(data: any): Promise<MasterKey>;
}

declare class Session<T extends Transport> {
    protected transport: T;
    protected masterKey: MasterKey;
    protected code: Uint8Array;
    constructor(transport: T, masterKey: MasterKey, code: Uint8Array);
    send(request: TransportRequest<T>): Promise<TransportResponse<T>>;
    toJSON(): any;
    static fromJSON<T extends Transport>(transport: T, json: any): Promise<Session<T>>;
    static fromJSON<T extends Transport>(transportConstructor: new () => T, json: any): Promise<Session<T>>;
}

declare class WalletProtocol<T extends Transport = Transport> extends EventEmitter {
    transport: T;
    constructor(transport: T);
    computeR(ra: Uint8Array, rb: Uint8Array): Promise<Uint8Array>;
    computeNx(): Promise<Uint8Array>;
    computeCx(pkeData: ProtocolPKEData, nx: Uint8Array, r: Uint8Array): Promise<Uint8Array>;
    validateAuthData(fullPkeData: ProtocolPKEData, fullAuthData: ProtocolAuthData): Promise<void>;
    computeMasterKey(ecdh: BaseECDH, fullPkeData: ProtocolPKEData, fullAuthData: ProtocolAuthData): Promise<MasterKey>;
    run(): Promise<Session<T>>;
    on(event: 'connString', listener: (connString: ConnectionString) => void): this;
    on(event: 'masterKey', listener: (masterKey: MasterKey) => void): this;
    on(event: 'finished', listener: () => void): this;
    emit(event: 'connString', connString: ConnectionString): boolean;
    emit(event: 'masterKey', masterKey: MasterKey): boolean;
    emit(event: 'finished'): boolean;
}

declare class ConnectionString {
    protected buffer: Uint8Array;
    protected l: number;
    constructor(buffer: Uint8Array, l: number);
    toString(): string;
    extractPort(): number;
    extractRb(): Uint8Array;
    static generate(port: number, l: number): Promise<ConnectionString>;
    static fromString(connString: string, l: number): ConnectionString;
}

interface Transport<Req = any, Res = any> {
    prepare: (protocol: WalletProtocol, publicKey: string) => Promise<PKEData>;
    publicKeyExchange: (protocol: WalletProtocol, pkeData: PKEData) => Promise<ProtocolPKEData>;
    authentication: (protocol: WalletProtocol, authData: AuthData) => Promise<ProtocolAuthData>;
    verification: (protocol: WalletProtocol, masterKey: MasterKey) => Promise<Uint8Array>;
    send: (masterKey: MasterKey, code: Uint8Array, request: Req) => Promise<Res>;
    finish: (protocol: WalletProtocol) => void;
}
type TransportRequest<T> = T extends Transport<infer Req> ? Req : never;
type TransportResponse<T> = T extends Transport<any, infer Res> ? Res : never;
declare abstract class BaseTransport<Req, Res> implements Transport<Req, Res> {
    abstract prepare(protocol: WalletProtocol, publicKey: string): Promise<PKEData>;
    abstract publicKeyExchange(protocol: WalletProtocol, publicKey: PKEData): Promise<ProtocolPKEData>;
    abstract authentication(protocol: WalletProtocol, authData: AuthData): Promise<ProtocolAuthData>;
    abstract verification(protocol: WalletProtocol, masterKey: MasterKey): Promise<Uint8Array>;
    send(masterKey: MasterKey, code: Uint8Array, req: Req): Promise<Res>;
    finish(protocol: WalletProtocol): void;
}

interface PublicKeyExchangeRequest {
    method: 'publicKeyExchange';
    sender: Identity$1;
    publicKey: string;
    ra?: string;
}
interface CommitmentRequest {
    method: 'commitment';
    cx: string;
}
interface NonceRevealRequest {
    method: 'nonce';
    nx: string;
}
interface VerificationRequest {
    method: 'verification';
}
interface VerificationChallengeRequest {
    method: 'verificationChallenge';
    ciphertext: string;
}
interface AcknowledgementRequest {
    method: 'acknowledgement';
}
type Request = PublicKeyExchangeRequest | CommitmentRequest | NonceRevealRequest | VerificationRequest | VerificationChallengeRequest | AcknowledgementRequest;

interface InitiatorOptions {
    host: string;
    id: Identity$1;
    l: number;
    getConnectionString: () => Promise<string>;
}
declare abstract class InitiatorTransport<Req, Res> extends BaseTransport<Req, Res> {
    protected opts: InitiatorOptions;
    connString: ConnectionString | undefined;
    constructor(opts?: Partial<InitiatorOptions>);
    abstract sendRequest<T extends Request>(request: Request): Promise<T>;
    prepare(protocol: WalletProtocol, publicKey: string): Promise<PKEData>;
    publicKeyExchange(protocol: WalletProtocol, pkeData: PKEData): Promise<ProtocolPKEData>;
    authentication(protocol: WalletProtocol, authData: AuthData): Promise<ProtocolAuthData>;
    verification(protocol: WalletProtocol, masterKey: MasterKey): Promise<Uint8Array>;
    finish(protocol: WalletProtocol): void;
}

interface HttpRequest {
    url: string;
    init?: RequestInit;
}
interface HttpResponse {
    status: number;
    body: string;
}
declare class HttpInitiatorTransport extends InitiatorTransport<HttpRequest, HttpResponse> {
    baseSend(port: number, httpReq: RequestInit): Promise<HttpResponse>;
    sendRequest<T extends Request>(request: Request): Promise<T>;
    send(masterKey: MasterKey, code: Uint8Array, req: HttpRequest): Promise<HttpResponse>;
}

type Params = Record<string, string> | undefined;
type Body = any;
interface ApiMethod {
    path: string;
    method: string;
    headers?: Record<string, string>;
}
interface ApiExecutor {
    executeQuery: <T>(api: ApiMethod, pathParams: Params, queryParams: Params, bodyObject: Body) => Promise<T>;
}

declare class IdentitiesApi {
    protected api: ApiExecutor;
    constructor(api: ApiExecutor);
    list(queryParams?: WalletPaths.IdentityList.QueryParameters): Promise<WalletPaths.IdentityList.Responses.$200>;
    select(queryParams?: WalletPaths.IdentitySelect.QueryParameters): Promise<WalletPaths.IdentitySelect.Responses.$200>;
    create(body: WalletPaths.IdentityCreate.RequestBody): Promise<WalletPaths.IdentityCreate.Responses.$201>;
    sign(pathParams: WalletPaths.IdentitySign.PathParameters, body: WalletPaths.IdentitySign.RequestBody): Promise<WalletPaths.IdentitySign.Responses.$200>;
    info(pathParams: WalletPaths.IdentityInfo.PathParameters): Promise<WalletPaths.IdentityInfo.Responses.$200>;
    deployTransaction(pathParams: WalletPaths.IdentityDeployTransaction.PathParameters, body: WalletPaths.IdentityDeployTransaction.RequestBody): Promise<WalletPaths.IdentityDeployTransaction.Responses.$200>;
}

declare class ResourcesApi {
    protected api: ApiExecutor;
    constructor(api: ApiExecutor);
    list(options?: WalletPaths.ResourceList.QueryParameters): Promise<WalletPaths.ResourceList.Responses.$200>;
    create(body: WalletPaths.ResourceCreate.RequestBody): Promise<WalletPaths.ResourceCreate.Responses.$201>;
}

declare class DisclosureApi {
    protected api: ApiExecutor;
    constructor(api: ApiExecutor);
    disclose(pathParams: WalletPaths.SelectiveDisclosure.PathParameters): Promise<WalletPaths.SelectiveDisclosure.Responses.$200>;
}

declare class TransactionApi {
    protected api: ApiExecutor;
    constructor(api: ApiExecutor);
    deploy(body: WalletPaths.TransactionDeploy.RequestBody): Promise<WalletPaths.TransactionDeploy.Responses.$200>;
}

declare class DidJwtApi {
    protected api: ApiExecutor;
    constructor(api: ApiExecutor);
    verify(body: WalletPaths.DidJwtVerify.RequestBody): Promise<WalletPaths.DidJwtVerify.Responses.$200>;
}

declare class ProviderInfoApi {
    protected api: ApiExecutor;
    constructor(api: ApiExecutor);
    get(): Promise<WalletPaths.ProviderinfoGet.Responses.$200>;
}

declare class WalletApi implements ApiExecutor {
    protected session: Session<HttpInitiatorTransport>;
    identities: IdentitiesApi;
    transaction: TransactionApi;
    resources: ResourcesApi;
    disclosure: DisclosureApi;
    didJwt: DidJwtApi;
    providerinfo: ProviderInfoApi;
    constructor(session: Session<HttpInitiatorTransport>);
    executeQuery<T>(api: ApiMethod, pathParams: Params, queryParams: Params, bodyObject: Body): Promise<T>;
}

declare class I3mWalletAgent extends EthersIoAgent {
    wallet: WalletApi;
    did: string;
    constructor(wallet: WalletApi, did: string, dltConfig?: Partial<Omit<DltConfig, 'rpcProviderUrl'>>);
}

declare class I3mWalletAgentDest extends I3mWalletAgent implements NrpDltAgentDest {
    getSecretFromLedger(secretLength: number, signerAddress: string, exchangeId: string, timeout: number): Promise<{
        hex: string;
        iat: number;
    }>;
}

/**
 * Agent base interface
 * @public
 */
interface IAgentBase {
    getSchema: () => IAgentPluginSchema;
    availableMethods: () => string[];
}
/**
 * Agent that can execute methods
 * @public
 */
interface IAgent extends IAgentBase {
    execute: <A = any, R = any>(method: string, args: A) => Promise<R>;
    emit: (eventType: string, data: any) => Promise<void>;
}
/**
 * Agent plugin method interface
 * @public
 */
interface IPluginMethod {
    (args: any, context: any): Promise<any>;
}
/**
 * Plugin method map interface
 * @public
 */
interface IPluginMethodMap extends Record<string, IPluginMethod> {
}
/**
 * Agent plugin schema
 * @public
 */
interface IAgentPluginSchema {
    components: {
        schemas: any;
        methods: any;
    };
}
/**
 * Removes context parameter from plugin method interface
 * @public
 */
interface RemoveContext<T extends IPluginMethod> {
    (args?: Parameters<T>[0] | undefined): ReturnType<T>;
}
/**
 * Utility type for constructing agent type that has a list of available methods
 * @public
 */
declare type TAgent<T extends IPluginMethodMap> = {
    [P in keyof T]: RemoveContext<T[P]>;
} & IAgent;
/**
 * Standard plugin method context interface
 *
 * @remarks
 * When executing plugin method, you don't need to pass in the context.
 * It is done automatically by the agent
 *
 * @example
 * ```typescript
 * await agent.resolveDid({
 *   didUrl: 'did:example:123'
 * })
 * ```
 * @public
 */
interface IAgentContext<T extends IPluginMethodMap> {
    /**
     * Configured agent
     */
    agent: TAgent<T>;
}

/**
 * Verifiable Credential {@link https://github.com/decentralized-identifier/did-jwt-vc}
 * @public
 */
interface VerifiableCredential {
    '@context': string[];
    id?: string;
    type: string[];
    issuer: {
        id: string;
        [x: string]: any;
    };
    issuanceDate: string;
    expirationDate?: string;
    credentialSubject: {
        id?: string;
        [x: string]: any;
    };
    credentialStatus?: {
        id: string;
        type: string;
    };
    proof: {
        type?: string;
        [x: string]: any;
    };
    [x: string]: any;
}
/**
 * Verifiable Presentation {@link https://github.com/decentralized-identifier/did-jwt-vc}
 * @public
 */
interface VerifiablePresentation {
    id?: string;
    holder: string;
    issuanceDate?: string;
    expirationDate?: string;
    '@context': string[];
    type: string[];
    verifier: string[];
    verifiableCredential: VerifiableCredential[];
    proof: {
        type?: string;
        [x: string]: any;
    };
    [x: string]: any;
}
/**
 * Message meta data
 * @public
 */
interface IMetaData {
    /**
     * Type
     */
    type: string;
    /**
     * Optional. Value
     */
    value?: string;
}
/**
 * DIDComm message
 * @public
 */
interface IMessage {
    /**
     * Unique message ID
     */
    id: string;
    /**
     * Message type
     */
    type: string;
    /**
     * Optional. Creation date (ISO 8601)
     */
    createdAt?: string;
    /**
     * Optional. Expiration date (ISO 8601)
     */
    expiresAt?: string;
    /**
     * Optional. Thread ID
     */
    threadId?: string;
    /**
     * Optional. Original message raw data
     */
    raw?: string;
    /**
     * Optional. Parsed data
     */
    data?: object | null;
    /**
     * Optional. List of DIDs to reply to
     */
    replyTo?: string[];
    /**
     * Optional. URL to post a reply message to
     */
    replyUrl?: string;
    /**
     * Optional. Sender DID
     */
    from?: string;
    /**
     * Optional. Recipient DID
     */
    to?: string;
    /**
     * Optional. Array of message metadata
     */
    metaData?: IMetaData[] | null;
    /**
     * Optional. Array of attached verifiable credentials
     */
    credentials?: VerifiableCredential[];
    /**
     * Optional. Array of attached verifiable presentations
     */
    presentations?: VerifiablePresentation[];
}

/**
 * Input arguments for {@link IDataStore.dataStoreSaveMessage | dataStoreSaveMessage}
 * @public
 */
interface IDataStoreSaveMessageArgs {
    /**
     * Required. Message
     */
    message: IMessage;
}
/**
 * Input arguments for {@link IDataStore.dataStoreGetMessage | dataStoreGetMessage}
 * @public
 */
interface IDataStoreGetMessageArgs {
    /**
     * Required. Message ID
     */
    id: string;
}
/**
 * Input arguments for {@link IDataStore.dataStoreSaveVerifiableCredential | dataStoreSaveVerifiableCredential}
 * @public
 */
interface IDataStoreSaveVerifiableCredentialArgs {
    /**
     * Required. VerifiableCredential
     */
    verifiableCredential: VerifiableCredential;
}
/**
 * Input arguments for {@link IDataStore.dataStoreGetVerifiableCredential | dataStoreGetVerifiableCredential}
 * @public
 */
interface IDataStoreGetVerifiableCredentialArgs {
    /**
     * Required. VerifiableCredential hash
     */
    hash: string;
}
/**
 * Input arguments for {@link IDataStore.dataStoreSaveVerifiablePresentation | dataStoreSaveVerifiablePresentation}
 * @public
 */
interface IDataStoreSaveVerifiablePresentationArgs {
    /**
     * Required. VerifiablePresentation
     */
    verifiablePresentation: VerifiablePresentation;
}
/**
 * Input arguments for {@link IDataStore.dataStoreGetVerifiablePresentation | dataStoreGetVerifiablePresentation}
 * @public
 */
interface IDataStoreGetVerifiablePresentationArgs {
    /**
     * Required. VerifiablePresentation hash
     */
    hash: string;
}
/**
 * Basic data store interface
 * @public
 */
interface IDataStore extends IPluginMethodMap {
    /**
     * Saves message to the data store
     * @param args - message
     * @returns a promise that resolves to the id of the message
     */
    dataStoreSaveMessage(args: IDataStoreSaveMessageArgs): Promise<string>;
    /**
     * Gets message from the data store
     * @param args - arguments for getting message
     * @returns a promise that resolves to the message
     */
    dataStoreGetMessage(args: IDataStoreGetMessageArgs): Promise<IMessage>;
    /**
     * Saves verifiable credential to the data store
     * @param args - verifiable credential
     * @returns a promise that resolves to the hash of the VerifiableCredential
     */
    dataStoreSaveVerifiableCredential(args: IDataStoreSaveVerifiableCredentialArgs): Promise<string>;
    /**
     * Gets verifiable credential from the data store
     * @param args - arguments for getting verifiable credential
     * @returns a promise that resolves to the verifiable credential
     */
    dataStoreGetVerifiableCredential(args: IDataStoreGetVerifiableCredentialArgs): Promise<VerifiableCredential>;
    /**
     * Saves verifiable presentation to the data store
     * @param args - verifiable presentation
     * @returns a promise that resolves to the hash of the VerifiablePresentation
     */
    dataStoreSaveVerifiablePresentation(args: IDataStoreSaveVerifiablePresentationArgs): Promise<string>;
    /**
     * Gets verifiable presentation from the data store
     * @param args - arguments for getting Verifiable Presentation
     * @returns a promise that resolves to the Verifiable Presentation
     */
    dataStoreGetVerifiablePresentation(args: IDataStoreGetVerifiablePresentationArgs): Promise<VerifiablePresentation>;
}

/**
 * Identifier interface
 * @public
 */
interface IIdentifier {
    /**
     * Decentralized identifier
     */
    did: string;
    /**
     * Optional. Identifier alias. Can be used to reference an object in an external system
     */
    alias?: string;
    /**
     * Identifier provider name
     */
    provider: string;
    /**
     * Controller key id
     */
    controllerKeyId?: string;
    /**
     * Array of managed keys
     */
    keys: IKey[];
    /**
     * Array of services
     */
    services: IService[];
}
/**
 * Cryptographic key type
 * @public
 */
declare type TKeyType = 'Ed25519' | 'Secp256k1';
/**
 * Cryptographic key
 * @public
 */
interface IKey {
    /**
     * Key ID
     */
    kid: string;
    /**
     * Key Management System
     */
    kms: string;
    /**
     * Key type
     */
    type: TKeyType;
    /**
     * Public key
     */
    publicKeyHex: string;
    /**
     * Optional. Private key
     */
    privateKeyHex?: string;
    /**
     * Optional. Key metadata. Can be used to store auth data to access remote kms
     */
    meta?: object | null;
}
/**
 * Identifier service
 * @public
 */
interface IService {
    /**
     * ID
     */
    id: string;
    /**
     * Service type
     */
    type: string;
    /**
     * Endpoint URL
     */
    serviceEndpoint: string;
    /**
     * Optional. Description
     */
    description?: string;
}

/**
 * Input arguments for {@link IKeyManager.keyManagerCreate | keyManagerCreate}
 * @public
 */
interface IKeyManagerCreateArgs {
    /**
     * Key type
     */
    type: TKeyType;
    /**
     * Key Management System
     */
    kms: string;
    /**
     * Optional. Key meta data
     */
    meta?: object;
}
/**
 * Input arguments for {@link IKeyManager.keyManagerGet | keyManagerGet}
 * @public
 */
interface IKeyManagerGetArgs {
    /**
     * Key ID
     */
    kid: string;
}
/**
 * Input arguments for {@link IKeyManager.keyManagerDelete | keyManagerDelete}
 * @public
 */
interface IKeyManagerDeleteArgs {
    /**
     * Key ID
     */
    kid: string;
}
/**
 * Input arguments for {@link IKeyManager.keyManagerEncryptJWE | keyManagerEncryptJWE}
 * @beta
 */
interface IKeyManagerEncryptJWEArgs {
    /**
     * Key ID to use for encryption
     */
    kid: string;
    /**
     * Recipient key object
     */
    to: Omit<IKey, 'kms'>;
    /**
     * Data to encrypt
     */
    data: string;
}
/**
 * Input arguments for {@link IKeyManager.keyManagerDecryptJWE | keyManagerDecryptJWE}
 * @beta
 */
interface IKeyManagerDecryptJWEArgs {
    /**
     * Key ID
     */
    kid: string;
    /**
     * Encrypted data
     */
    data: string;
}
/**
 * Input arguments for {@link IKeyManager.keyManagerSignJWT | keyManagerSignJWT}
 * @public
 */
interface IKeyManagerSignJWTArgs {
    /**
     * Key ID
     */
    kid: string;
    /**
     * Data to sign
     */
    data: string | Uint8Array;
}
/**
 * Input arguments for {@link IKeyManager.keyManagerSignEthTX | keyManagerSignEthTX}
 * @public
 */
interface IKeyManagerSignEthTXArgs {
    /**
     * Key ID
     */
    kid: string;
    /**
     * Ethereum transaction object
     */
    transaction: object;
}
/**
 * Key manager interface
 * @public
 */
interface IKeyManager extends IPluginMethodMap {
    /**
     * Lists available key management systems
     */
    keyManagerGetKeyManagementSystems(): Promise<Array<string>>;
    /**
     * Creates and returns a new key
     */
    keyManagerCreate(args: IKeyManagerCreateArgs): Promise<IKey>;
    /**
     * Returns an existing key
     */
    keyManagerGet(args: IKeyManagerGetArgs): Promise<IKey>;
    /**
     * Deletes a key
     */
    keyManagerDelete(args: IKeyManagerDeleteArgs): Promise<boolean>;
    /**
     * Imports a created key
     */
    keyManagerImport(args: IKey): Promise<boolean>;
    /**
     * Encrypts data
     * @beta
     */
    keyManagerEncryptJWE(args: IKeyManagerEncryptJWEArgs): Promise<string>;
    /**
     * Decrypts data
     * @beta
     */
    keyManagerDecryptJWE(args: IKeyManagerDecryptJWEArgs): Promise<string>;
    /**
     * Signs JWT
     */
    keyManagerSignJWT(args: IKeyManagerSignJWTArgs): Promise<string>;
    /** Signs Ethereum transaction */
    keyManagerSignEthTX(args: IKeyManagerSignEthTXArgs): Promise<string>;
}

/**
 * Input arguments for {@link IDIDManager.didManagerGet | didManagerGet}
 * @public
 */
interface IDIDManagerGetArgs {
    /**
     * DID
     */
    did: string;
}
/**
 * Input arguments for {@link IDIDManager.didManagerFind | didManagerFind}
 * @public
 */
interface IDIDManagerFindArgs {
    /**
     * Optional. Alias
     */
    alias?: string;
    /**
     * Optional. Provider
     */
    provider?: string;
}
/**
 * Input arguments for {@link IDIDManager.didManagerGetByAlias | didManagerGetByAlias}
 * @public
 */
interface IDIDManagerGetByAliasArgs {
    /**
     * Alias
     */
    alias: string;
    /**
     * Optional provider
     */
    provider?: string;
}
/**
 * Input arguments for {@link IDIDManager.didManagerDelete | didManagerDelete}
 * @public
 */
interface IDIDManagerDeleteArgs {
    /**
     * DID
     */
    did: string;
}
/**
 * Input arguments for {@link IDIDManager.didManagerCreate | didManagerCreate}
 * @public
 */
interface IDIDManagerCreateArgs {
    /**
     * Optional. Identifier alias. Can be used to reference an object in an external system
     */
    alias?: string;
    /**
     * Optional. Identifier provider
     */
    provider?: string;
    /**
     * Optional. Key Management System
     */
    kms?: string;
    /**
     * Optional. Identifier provider specific options
     */
    options?: object;
}
/**
 * Input arguments for {@link IDIDManager.didManagerSetAlias | didManagerSetAlias}
 * @public
 */
interface IDIDManagerSetAliasArgs {
    /**
     * Required. DID
     */
    did: string;
    /**
     * Required. Identifier alias
     */
    alias: string;
}
/**
 * Input arguments for {@link IDIDManager.didManagerGetOrCreate | didManagerGetOrCreate}
 * @public
 */
interface IDIDManagerGetOrCreateArgs {
    /**
     * Identifier alias. Can be used to reference an object in an external system
     */
    alias: string;
    /**
     * Optional. Identifier provider
     */
    provider?: string;
    /**
     * Optional. Key Management System
     */
    kms?: string;
    /**
     * Optional. Identifier provider specific options
     */
    options?: object;
}
/**
 * Input arguments for {@link IDIDManager.didManagerAddKey | didManagerAddKey}
 * @public
 */
interface IDIDManagerAddKeyArgs {
    /**
     * DID
     */
    did: string;
    /**
     * Key object
     */
    key: IKey;
    /**
     * Optional. Identifier provider specific options
     */
    options?: object;
}
/**
 * Input arguments for {@link IDIDManager.didManagerRemoveKey | didManagerRemoveKey}
 * @public
 */
interface IDIDManagerRemoveKeyArgs {
    /**
     * DID
     */
    did: string;
    /**
     * Key ID
     */
    kid: string;
    /**
     * Optional. Identifier provider specific options
     */
    options?: object;
}
/**
 * Input arguments for {@link IDIDManager.didManagerAddService | didManagerAddService}
 * @public
 */
interface IDIDManagerAddServiceArgs {
    /**
     * DID
     */
    did: string;
    /**
     * Service object
     */
    service: IService;
    /**
     * Optional. Identifier provider specific options
     */
    options?: object;
}
/**
 * Input arguments for {@link IDIDManager.didManagerRemoveService | didManagerRemoveService}
 * @public
 */
interface IDIDManagerRemoveServiceArgs {
    /**
     * DID
     */
    did: string;
    /**
     * Service ID
     */
    id: string;
    /**
     * Optional. Identifier provider specific options
     */
    options?: object;
}
/**
 * Identifier manager interface
 * @public
 */
interface IDIDManager extends IPluginMethodMap {
    /**
     * Returns a list of available identifier providers
     */
    didManagerGetProviders(): Promise<Array<string>>;
    /**
     * Returns a list of managed identifiers
     *
     * @param args - Required. Arguments to get the list of identifiers
     * @param context - <a href="/docs/agent/plugins#executing-plugin-methods">Execution context</a>. Requires `agent` that has {@link @veramo/core#IKeyManager} methods
     *
     * @example
     * ```typescript
     * const aliceIdentifiers = await agent.didManagerFind({
     *   alias: 'alice'
     * })
     *
     * const rinkebyIdentifiers = await agent.didManagerFind({
     *   provider: 'did:ethr:rinkeby'
     * })
     * ```
     */
    didManagerFind(args: IDIDManagerFindArgs): Promise<Array<IIdentifier>>;
    /**
     * Returns a specific identifier
     */
    didManagerGet(args: IDIDManagerGetArgs): Promise<IIdentifier>;
    /**
     * Returns a specific identifier by alias
     *
     * @param args - Required. Arguments to get the identifier
     * @param context - <a href="/docs/agent/plugins#executing-plugin-methods">Execution context</a>. Requires `agent` that has {@link @veramo/core#IKeyManager} methods
     *
     * @example
     * ```typescript
     * const identifier = await agent.didManagerGetByAlias({
     *   alias: 'alice',
     *   provider: 'did:ethr:rinkeby'
     * })
     * ```
     */
    didManagerGetByAlias(args: IDIDManagerGetByAliasArgs): Promise<IIdentifier>;
    /**
     * Creates and returns a new identifier
     *
     * @param args - Required. Arguments to create the identifier
     * @param context - <a href="/docs/agent/plugins#executing-plugin-methods">Execution context</a>. Requires `agent` that has {@link @veramo/core#IKeyManager} methods
     *
     * @example
     * ```typescript
     * const identifier = await agent.didManagerCreate({
     *   alias: 'alice',
     *   provider: 'did:ethr:rinkeby',
     *   kms: 'local'
     * })
     * ```
     */
    didManagerCreate(args: IDIDManagerCreateArgs, context: IAgentContext<IKeyManager>): Promise<IIdentifier>;
    /**
     * Sets identifier alias
     *
     * @param args - Required. Arguments to set identifier alias
     * @param context - <a href="/docs/agent/plugins#executing-plugin-methods">Execution context</a>. Requires `agent` that has {@link @veramo/core#IKeyManager} methods
     *
     * @example
     * ```typescript
     * const identifier = await agent.didManagerCreate()
     * const result = await agent.didManagerSetAlias({
     *   did: identifier.did,
     *   alias: 'carol',
     * })
     * ```
     */
    didManagerSetAlias(args: IDIDManagerSetAliasArgs, context: IAgentContext<IKeyManager>): Promise<boolean>;
    /**
     * Returns an existing identifier or creates a new one for a specific alias
     */
    didManagerGetOrCreate(args: IDIDManagerGetOrCreateArgs, context: IAgentContext<IKeyManager>): Promise<IIdentifier>;
    /**
     * Imports identifier
     */
    didManagerImport(args: IIdentifier, context: IAgentContext<IKeyManager>): Promise<IIdentifier>;
    /**
     * Deletes identifier
     */
    didManagerDelete(args: IDIDManagerDeleteArgs, context: IAgentContext<IKeyManager>): Promise<boolean>;
    /**
     * Adds a key to a DID Document
     * @returns identifier provider specific response. Can be txHash, etc,
     */
    didManagerAddKey(args: IDIDManagerAddKeyArgs, context: IAgentContext<IKeyManager>): Promise<any>;
    /**
     * Removes a key from a DID Document
     * @returns identifier provider specific response. Can be txHash, etc,
     */
    didManagerRemoveKey(args: IDIDManagerRemoveKeyArgs, context: IAgentContext<IKeyManager>): Promise<any>;
    /**
     * Adds a service to a DID Document
     * @returns identifier provider specific response. Can be txHash, etc,
     */
    didManagerAddService(args: IDIDManagerAddServiceArgs, context: IAgentContext<IKeyManager>): Promise<any>;
    /**
     * Removes a service from a DID Document
     * @returns identifier provider specific response. Can be txHash, etc,
     */
    didManagerRemoveService(args: IDIDManagerRemoveServiceArgs, context: IAgentContext<IKeyManager>): Promise<any>;
}

/**
 * Input arguments for {@link IMessageHandler.handleMessage | handleMessage}
 * @public
 */
interface IHandleMessageArgs {
    /**
     * Raw message data
     */
    raw: string;
    /**
     * Optional. Message meta data
     */
    metaData?: IMetaData[];
    /**
     * Optional. If set to `true`, the message will be saved using {@link IDataStore.dataStoreSaveMessage | dataStoreSaveMessage}
     */
    save?: boolean;
}
/**
 * Message handler interface
 * @public
 */
interface IMessageHandler extends IPluginMethodMap {
    /**
     * Parses and optionally saves a message
     * @param context - Execution context. Requires agent with {@link @veramo/core#IDataStore} methods
     */
    handleMessage(args: IHandleMessageArgs, context: IAgentContext<IDataStore>): Promise<IMessage>;
}

declare type Extensible = Record<string, any>;
interface DIDResolutionResult {
    '@context'?: 'https://w3id.org/did-resolution/v1' | string | string[];
    didResolutionMetadata: DIDResolutionMetadata;
    didDocument: DIDDocument | null;
    didDocumentMetadata: DIDDocumentMetadata;
}
interface DIDResolutionOptions extends Extensible {
    accept?: string;
}
interface DIDResolutionMetadata extends Extensible {
    contentType?: string;
    error?: 'invalidDid' | 'notFound' | 'representationNotSupported' | 'unsupportedDidMethod' | string;
}
interface DIDDocumentMetadata extends Extensible {
    created?: string;
    updated?: string;
    deactivated?: boolean;
    versionId?: string;
    nextUpdate?: string;
    nextVersionId?: string;
    equivalentId?: string;
    canonicalId?: string;
}
declare type KeyCapabilitySection = 'authentication' | 'assertionMethod' | 'keyAgreement' | 'capabilityInvocation' | 'capabilityDelegation';
declare type DIDDocument = {
    '@context'?: 'https://www.w3.org/ns/did/v1' | string | string[];
    id: string;
    alsoKnownAs?: string[];
    controller?: string | string[];
    verificationMethod?: VerificationMethod[];
    service?: ServiceEndpoint[];
    /**
     * @deprecated
     */
    publicKey?: VerificationMethod[];
} & {
    [x in KeyCapabilitySection]?: (string | VerificationMethod)[];
};
interface ServiceEndpoint {
    id: string;
    type: string;
    serviceEndpoint: string;
    description?: string;
}
/**
 * Encapsulates a JSON web key type that includes only the public properties that
 * can be used in DID documents.
 *
 * The private properties are intentionally omitted to discourage the use
 * (and accidental disclosure) of private keys in DID documents.
 */
interface JsonWebKey extends Extensible {
    alg?: string;
    crv?: string;
    e?: string;
    ext?: boolean;
    key_ops?: string[];
    kid?: string;
    kty: string;
    n?: string;
    use?: string;
    x?: string;
    y?: string;
}
interface VerificationMethod {
    id: string;
    type: string;
    controller: string;
    publicKeyBase58?: string;
    publicKeyBase64?: string;
    publicKeyJwk?: JsonWebKey;
    publicKeyHex?: string;
    publicKeyMultibase?: string;
    blockchainAccountId?: string;
    ethereumAddress?: string;
}

/**
 * Input arguments for {@link IResolver.resolveDid | resolveDid}
 * @public
 */
interface ResolveDidArgs {
    /**
     * DID URL
     *
     * @example
     * `did:web:uport.me`
     */
    didUrl: string;
    /**
     * DID resolution options that will be passed to the method specific resolver.
     * See: https://w3c.github.io/did-spec-registries/#did-resolution-input-metadata
     * See: https://www.w3.org/TR/did-core/#did-resolution-options
     */
    options?: DIDResolutionOptions;
}
/**
 * DID Resolver interface
 * @public
 */
interface IResolver extends IPluginMethodMap {
    /**
     * Resolves DID and returns DID Document
     *
     * @example
     * ```typescript
     * const doc = await agent.resolveDid({
     *   didUrl: 'did:ethr:rinkeby:0xb09b66026ba5909a7cfe99b76875431d2b8d5190'
     * })
     * expect(doc.didDocument).toEqual({
     *   '@context': [
     *     'https://www.w3.org/ns/did/v1',
     *     'https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/lds-ecdsa-secp256k1-recovery2020-0.0.jsonld',
     *   ],
     *   id: 'did:ethr:rinkeby:0xb09b66026ba5909a7cfe99b76875431d2b8d5190',
     *   verificationMethod: [
     *     {
     *       id: 'did:ethr:rinkeby:0xb09b66026ba5909a7cfe99b76875431d2b8d5190#controller',
     *       type: 'EcdsaSecp256k1RecoveryMethod2020',
     *       controller: 'did:ethr:rinkeby:0xb09b66026ba5909a7cfe99b76875431d2b8d5190',
     *       blockchainAccountId: '0xb09B66026bA5909A7CFE99b76875431D2b8D5190@eip155:4',
     *     },
     *   ],
     *   authentication: ['did:ethr:rinkeby:0xb09b66026ba5909a7cfe99b76875431d2b8d5190#controller'],
     *   assertionMethod: ['did:ethr:rinkeby:0xb09b66026ba5909a7cfe99b76875431d2b8d5190#controller'],
     * })
     * ```
     *
     * @param args - Input arguments for resolving a DID
     * @public
     */
    resolveDid(args: ResolveDidArgs): Promise<DIDResolutionResult>;
}

/**
 * An abstract class for the {@link @veramo/did-manager#DIDManager} identifier providers
 * @public
 */
declare abstract class AbstractIdentifierProvider {
    abstract createIdentifier(args: {
        kms?: string;
        alias?: string;
        options?: any;
    }, context: IAgentContext<IKeyManager>): Promise<Omit<IIdentifier, 'provider'>>;
    abstract deleteIdentifier(args: IIdentifier, context: IAgentContext<IKeyManager>): Promise<boolean>;
    abstract addKey(args: {
        identifier: IIdentifier;
        key: IKey;
        options?: any;
    }, context: IAgentContext<IKeyManager>): Promise<any>;
    abstract removeKey(args: {
        identifier: IIdentifier;
        kid: string;
        options?: any;
    }, context: IAgentContext<IKeyManager>): Promise<any>;
    abstract addService(args: {
        identifier: IIdentifier;
        service: IService;
        options?: any;
    }, context: IAgentContext<IKeyManager>): Promise<any>;
    abstract removeService(args: {
        identifier: IIdentifier;
        id: string;
        options?: any;
    }, context: IAgentContext<IKeyManager>): Promise<any>;
}

/*! *****************************************************************************
Copyright (C) Microsoft. All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at http://www.apache.org/licenses/LICENSE-2.0

THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION ANY IMPLIED
WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A PARTICULAR PURPOSE,
MERCHANTABLITY OR NON-INFRINGEMENT.

See the Apache Version 2.0 License for specific language governing permissions
and limitations under the License.
***************************************************************************** */


declare global {
    namespace Reflect {
        /**
          * Applies a set of decorators to a target object.
          * @param decorators An array of decorators.
          * @param target The target object.
          * @returns The result of applying the provided decorators.
          * @remarks Decorators are applied in reverse order of their positions in the array.
          * @example
          *
          *     class Example { }
          *
          *     // constructor
          *     Example = Reflect.decorate(decoratorsArray, Example);
          *
          */
        function decorate(decorators: ClassDecorator[], target: Function): Function;
        /**
          * Applies a set of decorators to a property of a target object.
          * @param decorators An array of decorators.
          * @param target The target object.
          * @param propertyKey The property key to decorate.
          * @param attributes A property descriptor.
          * @remarks Decorators are applied in reverse order.
          * @example
          *
          *     class Example {
          *         // property declarations are not part of ES6, though they are valid in TypeScript:
          *         // static staticProperty;
          *         // property;
          *
          *         static staticMethod() { }
          *         method() { }
          *     }
          *
          *     // property (on constructor)
          *     Reflect.decorate(decoratorsArray, Example, "staticProperty");
          *
          *     // property (on prototype)
          *     Reflect.decorate(decoratorsArray, Example.prototype, "property");
          *
          *     // method (on constructor)
          *     Object.defineProperty(Example, "staticMethod",
          *         Reflect.decorate(decoratorsArray, Example, "staticMethod",
          *             Object.getOwnPropertyDescriptor(Example, "staticMethod")));
          *
          *     // method (on prototype)
          *     Object.defineProperty(Example.prototype, "method",
          *         Reflect.decorate(decoratorsArray, Example.prototype, "method",
          *             Object.getOwnPropertyDescriptor(Example.prototype, "method")));
          *
          */
        function decorate(decorators: (PropertyDecorator | MethodDecorator)[], target: Object, propertyKey: string | symbol, attributes?: PropertyDescriptor): PropertyDescriptor;
        /**
          * A default metadata decorator factory that can be used on a class, class member, or parameter.
          * @param metadataKey The key for the metadata entry.
          * @param metadataValue The value for the metadata entry.
          * @returns A decorator function.
          * @remarks
          * If `metadataKey` is already defined for the target and target key, the
          * metadataValue for that key will be overwritten.
          * @example
          *
          *     // constructor
          *     @Reflect.metadata(key, value)
          *     class Example {
          *     }
          *
          *     // property (on constructor, TypeScript only)
          *     class Example {
          *         @Reflect.metadata(key, value)
          *         static staticProperty;
          *     }
          *
          *     // property (on prototype, TypeScript only)
          *     class Example {
          *         @Reflect.metadata(key, value)
          *         property;
          *     }
          *
          *     // method (on constructor)
          *     class Example {
          *         @Reflect.metadata(key, value)
          *         static staticMethod() { }
          *     }
          *
          *     // method (on prototype)
          *     class Example {
          *         @Reflect.metadata(key, value)
          *         method() { }
          *     }
          *
          */
        function metadata(metadataKey: any, metadataValue: any): {
            (target: Function): void;
            (target: Object, propertyKey: string | symbol): void;
        };
        /**
          * Define a unique metadata entry on the target.
          * @param metadataKey A key used to store and retrieve metadata.
          * @param metadataValue A value that contains attached metadata.
          * @param target The target object on which to define metadata.
          * @example
          *
          *     class Example {
          *     }
          *
          *     // constructor
          *     Reflect.defineMetadata("custom:annotation", options, Example);
          *
          *     // decorator factory as metadata-producing annotation.
          *     function MyAnnotation(options): ClassDecorator {
          *         return target => Reflect.defineMetadata("custom:annotation", options, target);
          *     }
          *
          */
        function defineMetadata(metadataKey: any, metadataValue: any, target: Object): void;
        /**
          * Define a unique metadata entry on the target.
          * @param metadataKey A key used to store and retrieve metadata.
          * @param metadataValue A value that contains attached metadata.
          * @param target The target object on which to define metadata.
          * @param propertyKey The property key for the target.
          * @example
          *
          *     class Example {
          *         // property declarations are not part of ES6, though they are valid in TypeScript:
          *         // static staticProperty;
          *         // property;
          *
          *         static staticMethod(p) { }
          *         method(p) { }
          *     }
          *
          *     // property (on constructor)
          *     Reflect.defineMetadata("custom:annotation", Number, Example, "staticProperty");
          *
          *     // property (on prototype)
          *     Reflect.defineMetadata("custom:annotation", Number, Example.prototype, "property");
          *
          *     // method (on constructor)
          *     Reflect.defineMetadata("custom:annotation", Number, Example, "staticMethod");
          *
          *     // method (on prototype)
          *     Reflect.defineMetadata("custom:annotation", Number, Example.prototype, "method");
          *
          *     // decorator factory as metadata-producing annotation.
          *     function MyAnnotation(options): PropertyDecorator {
          *         return (target, key) => Reflect.defineMetadata("custom:annotation", options, target, key);
          *     }
          *
          */
        function defineMetadata(metadataKey: any, metadataValue: any, target: Object, propertyKey: string | symbol): void;
        /**
          * Gets a value indicating whether the target object or its prototype chain has the provided metadata key defined.
          * @param metadataKey A key used to store and retrieve metadata.
          * @param target The target object on which the metadata is defined.
          * @returns `true` if the metadata key was defined on the target object or its prototype chain; otherwise, `false`.
          * @example
          *
          *     class Example {
          *     }
          *
          *     // constructor
          *     result = Reflect.hasMetadata("custom:annotation", Example);
          *
          */
        function hasMetadata(metadataKey: any, target: Object): boolean;
        /**
          * Gets a value indicating whether the target object or its prototype chain has the provided metadata key defined.
          * @param metadataKey A key used to store and retrieve metadata.
          * @param target The target object on which the metadata is defined.
          * @param propertyKey The property key for the target.
          * @returns `true` if the metadata key was defined on the target object or its prototype chain; otherwise, `false`.
          * @example
          *
          *     class Example {
          *         // property declarations are not part of ES6, though they are valid in TypeScript:
          *         // static staticProperty;
          *         // property;
          *
          *         static staticMethod(p) { }
          *         method(p) { }
          *     }
          *
          *     // property (on constructor)
          *     result = Reflect.hasMetadata("custom:annotation", Example, "staticProperty");
          *
          *     // property (on prototype)
          *     result = Reflect.hasMetadata("custom:annotation", Example.prototype, "property");
          *
          *     // method (on constructor)
          *     result = Reflect.hasMetadata("custom:annotation", Example, "staticMethod");
          *
          *     // method (on prototype)
          *     result = Reflect.hasMetadata("custom:annotation", Example.prototype, "method");
          *
          */
        function hasMetadata(metadataKey: any, target: Object, propertyKey: string | symbol): boolean;
        /**
          * Gets a value indicating whether the target object has the provided metadata key defined.
          * @param metadataKey A key used to store and retrieve metadata.
          * @param target The target object on which the metadata is defined.
          * @returns `true` if the metadata key was defined on the target object; otherwise, `false`.
          * @example
          *
          *     class Example {
          *     }
          *
          *     // constructor
          *     result = Reflect.hasOwnMetadata("custom:annotation", Example);
          *
          */
        function hasOwnMetadata(metadataKey: any, target: Object): boolean;
        /**
          * Gets a value indicating whether the target object has the provided metadata key defined.
          * @param metadataKey A key used to store and retrieve metadata.
          * @param target The target object on which the metadata is defined.
          * @param propertyKey The property key for the target.
          * @returns `true` if the metadata key was defined on the target object; otherwise, `false`.
          * @example
          *
          *     class Example {
          *         // property declarations are not part of ES6, though they are valid in TypeScript:
          *         // static staticProperty;
          *         // property;
          *
          *         static staticMethod(p) { }
          *         method(p) { }
          *     }
          *
          *     // property (on constructor)
          *     result = Reflect.hasOwnMetadata("custom:annotation", Example, "staticProperty");
          *
          *     // property (on prototype)
          *     result = Reflect.hasOwnMetadata("custom:annotation", Example.prototype, "property");
          *
          *     // method (on constructor)
          *     result = Reflect.hasOwnMetadata("custom:annotation", Example, "staticMethod");
          *
          *     // method (on prototype)
          *     result = Reflect.hasOwnMetadata("custom:annotation", Example.prototype, "method");
          *
          */
        function hasOwnMetadata(metadataKey: any, target: Object, propertyKey: string | symbol): boolean;
        /**
          * Gets the metadata value for the provided metadata key on the target object or its prototype chain.
          * @param metadataKey A key used to store and retrieve metadata.
          * @param target The target object on which the metadata is defined.
          * @returns The metadata value for the metadata key if found; otherwise, `undefined`.
          * @example
          *
          *     class Example {
          *     }
          *
          *     // constructor
          *     result = Reflect.getMetadata("custom:annotation", Example);
          *
          */
        function getMetadata(metadataKey: any, target: Object): any;
        /**
          * Gets the metadata value for the provided metadata key on the target object or its prototype chain.
          * @param metadataKey A key used to store and retrieve metadata.
          * @param target The target object on which the metadata is defined.
          * @param propertyKey The property key for the target.
          * @returns The metadata value for the metadata key if found; otherwise, `undefined`.
          * @example
          *
          *     class Example {
          *         // property declarations are not part of ES6, though they are valid in TypeScript:
          *         // static staticProperty;
          *         // property;
          *
          *         static staticMethod(p) { }
          *         method(p) { }
          *     }
          *
          *     // property (on constructor)
          *     result = Reflect.getMetadata("custom:annotation", Example, "staticProperty");
          *
          *     // property (on prototype)
          *     result = Reflect.getMetadata("custom:annotation", Example.prototype, "property");
          *
          *     // method (on constructor)
          *     result = Reflect.getMetadata("custom:annotation", Example, "staticMethod");
          *
          *     // method (on prototype)
          *     result = Reflect.getMetadata("custom:annotation", Example.prototype, "method");
          *
          */
        function getMetadata(metadataKey: any, target: Object, propertyKey: string | symbol): any;
        /**
          * Gets the metadata value for the provided metadata key on the target object.
          * @param metadataKey A key used to store and retrieve metadata.
          * @param target The target object on which the metadata is defined.
          * @returns The metadata value for the metadata key if found; otherwise, `undefined`.
          * @example
          *
          *     class Example {
          *     }
          *
          *     // constructor
          *     result = Reflect.getOwnMetadata("custom:annotation", Example);
          *
          */
        function getOwnMetadata(metadataKey: any, target: Object): any;
        /**
          * Gets the metadata value for the provided metadata key on the target object.
          * @param metadataKey A key used to store and retrieve metadata.
          * @param target The target object on which the metadata is defined.
          * @param propertyKey The property key for the target.
          * @returns The metadata value for the metadata key if found; otherwise, `undefined`.
          * @example
          *
          *     class Example {
          *         // property declarations are not part of ES6, though they are valid in TypeScript:
          *         // static staticProperty;
          *         // property;
          *
          *         static staticMethod(p) { }
          *         method(p) { }
          *     }
          *
          *     // property (on constructor)
          *     result = Reflect.getOwnMetadata("custom:annotation", Example, "staticProperty");
          *
          *     // property (on prototype)
          *     result = Reflect.getOwnMetadata("custom:annotation", Example.prototype, "property");
          *
          *     // method (on constructor)
          *     result = Reflect.getOwnMetadata("custom:annotation", Example, "staticMethod");
          *
          *     // method (on prototype)
          *     result = Reflect.getOwnMetadata("custom:annotation", Example.prototype, "method");
          *
          */
        function getOwnMetadata(metadataKey: any, target: Object, propertyKey: string | symbol): any;
        /**
          * Gets the metadata keys defined on the target object or its prototype chain.
          * @param target The target object on which the metadata is defined.
          * @returns An array of unique metadata keys.
          * @example
          *
          *     class Example {
          *     }
          *
          *     // constructor
          *     result = Reflect.getMetadataKeys(Example);
          *
          */
        function getMetadataKeys(target: Object): any[];
        /**
          * Gets the metadata keys defined on the target object or its prototype chain.
          * @param target The target object on which the metadata is defined.
          * @param propertyKey The property key for the target.
          * @returns An array of unique metadata keys.
          * @example
          *
          *     class Example {
          *         // property declarations are not part of ES6, though they are valid in TypeScript:
          *         // static staticProperty;
          *         // property;
          *
          *         static staticMethod(p) { }
          *         method(p) { }
          *     }
          *
          *     // property (on constructor)
          *     result = Reflect.getMetadataKeys(Example, "staticProperty");
          *
          *     // property (on prototype)
          *     result = Reflect.getMetadataKeys(Example.prototype, "property");
          *
          *     // method (on constructor)
          *     result = Reflect.getMetadataKeys(Example, "staticMethod");
          *
          *     // method (on prototype)
          *     result = Reflect.getMetadataKeys(Example.prototype, "method");
          *
          */
        function getMetadataKeys(target: Object, propertyKey: string | symbol): any[];
        /**
          * Gets the unique metadata keys defined on the target object.
          * @param target The target object on which the metadata is defined.
          * @returns An array of unique metadata keys.
          * @example
          *
          *     class Example {
          *     }
          *
          *     // constructor
          *     result = Reflect.getOwnMetadataKeys(Example);
          *
          */
        function getOwnMetadataKeys(target: Object): any[];
        /**
          * Gets the unique metadata keys defined on the target object.
          * @param target The target object on which the metadata is defined.
          * @param propertyKey The property key for the target.
          * @returns An array of unique metadata keys.
          * @example
          *
          *     class Example {
          *         // property declarations are not part of ES6, though they are valid in TypeScript:
          *         // static staticProperty;
          *         // property;
          *
          *         static staticMethod(p) { }
          *         method(p) { }
          *     }
          *
          *     // property (on constructor)
          *     result = Reflect.getOwnMetadataKeys(Example, "staticProperty");
          *
          *     // property (on prototype)
          *     result = Reflect.getOwnMetadataKeys(Example.prototype, "property");
          *
          *     // method (on constructor)
          *     result = Reflect.getOwnMetadataKeys(Example, "staticMethod");
          *
          *     // method (on prototype)
          *     result = Reflect.getOwnMetadataKeys(Example.prototype, "method");
          *
          */
        function getOwnMetadataKeys(target: Object, propertyKey: string | symbol): any[];
        /**
          * Deletes the metadata entry from the target object with the provided key.
          * @param metadataKey A key used to store and retrieve metadata.
          * @param target The target object on which the metadata is defined.
          * @returns `true` if the metadata entry was found and deleted; otherwise, false.
          * @example
          *
          *     class Example {
          *     }
          *
          *     // constructor
          *     result = Reflect.deleteMetadata("custom:annotation", Example);
          *
          */
        function deleteMetadata(metadataKey: any, target: Object): boolean;
        /**
          * Deletes the metadata entry from the target object with the provided key.
          * @param metadataKey A key used to store and retrieve metadata.
          * @param target The target object on which the metadata is defined.
          * @param propertyKey The property key for the target.
          * @returns `true` if the metadata entry was found and deleted; otherwise, false.
          * @example
          *
          *     class Example {
          *         // property declarations are not part of ES6, though they are valid in TypeScript:
          *         // static staticProperty;
          *         // property;
          *
          *         static staticMethod(p) { }
          *         method(p) { }
          *     }
          *
          *     // property (on constructor)
          *     result = Reflect.deleteMetadata("custom:annotation", Example, "staticProperty");
          *
          *     // property (on prototype)
          *     result = Reflect.deleteMetadata("custom:annotation", Example.prototype, "property");
          *
          *     // method (on constructor)
          *     result = Reflect.deleteMetadata("custom:annotation", Example, "staticMethod");
          *
          *     // method (on prototype)
          *     result = Reflect.deleteMetadata("custom:annotation", Example.prototype, "method");
          *
          */
        function deleteMetadata(metadataKey: any, target: Object, propertyKey: string | symbol): boolean;
    }
}

interface Order<TColumns> {
    column: TColumns;
    direction: 'ASC' | 'DESC';
}
interface Where<TColumns> {
    column: TColumns;
    value?: string[];
    not?: boolean;
    op?: 'LessThan' | 'LessThanOrEqual' | 'MoreThan' | 'MoreThanOrEqual' | 'Equal' | 'Like' | 'Between' | 'In' | 'Any' | 'IsNull';
}
interface FindArgs<TColumns> {
    where?: Where<TColumns>[];
    order?: Order<TColumns>[];
    take?: number;
    skip?: number;
}
declare type TIdentifiersColumns = 'did' | 'alias' | 'provider';
declare type TMessageColumns = 'from' | 'to' | 'id' | 'createdAt' | 'expiresAt' | 'threadId' | 'type' | 'raw' | 'replyTo' | 'replyUrl';
declare type TCredentialColumns = 'context' | 'type' | 'id' | 'issuer' | 'subject' | 'expirationDate' | 'issuanceDate';
declare type TClaimsColumns = 'context' | 'credentialType' | 'type' | 'value' | 'isObj' | 'id' | 'issuer' | 'subject' | 'expirationDate' | 'issuanceDate';
declare type TPresentationColumns = 'context' | 'type' | 'id' | 'holder' | 'verifier' | 'expirationDate' | 'issuanceDate';

interface IContext$1 {
    authenticatedDid?: string;
}
interface UniqueVerifiableCredential {
    hash: string;
    verifiableCredential: VerifiableCredential;
}
interface UniqueVerifiablePresentation {
    hash: string;
    verifiablePresentation: VerifiablePresentation;
}
declare type FindIdentifiersArgs = FindArgs<TIdentifiersColumns>;
declare type FindMessagesArgs = FindArgs<TMessageColumns>;
declare type FindClaimsArgs = FindArgs<TClaimsColumns>;
declare type FindCredentialsArgs = FindArgs<TCredentialColumns>;
declare type FindPresentationsArgs = FindArgs<TPresentationColumns>;
declare type PartialIdentifier = Partial<IIdentifier>;
interface IDataStoreORM extends IPluginMethodMap {
    dataStoreORMGetIdentifiers(args: FindIdentifiersArgs, context: IContext$1): Promise<Array<PartialIdentifier>>;
    dataStoreORMGetIdentifiersCount(args: FindIdentifiersArgs, context: IContext$1): Promise<number>;
    dataStoreORMGetMessages(args: FindMessagesArgs, context: IContext$1): Promise<Array<IMessage>>;
    dataStoreORMGetMessagesCount(args: FindMessagesArgs, context: IContext$1): Promise<number>;
    dataStoreORMGetVerifiableCredentialsByClaims(args: FindClaimsArgs, context: IContext$1): Promise<Array<UniqueVerifiableCredential>>;
    dataStoreORMGetVerifiableCredentialsByClaimsCount(args: FindClaimsArgs, context: IContext$1): Promise<number>;
    dataStoreORMGetVerifiableCredentials(args: FindCredentialsArgs, context: IContext$1): Promise<Array<UniqueVerifiableCredential>>;
    dataStoreORMGetVerifiableCredentialsCount(args: FindCredentialsArgs, context: IContext$1): Promise<number>;
    dataStoreORMGetVerifiablePresentations(args: FindPresentationsArgs, context: IContext$1): Promise<Array<UniqueVerifiablePresentation>>;
    dataStoreORMGetVerifiablePresentationsCount(args: FindPresentationsArgs, context: IContext$1): Promise<number>;
}

/**
 * The type of encoding to be used for the Verifiable Credential or Presentation to be generated.
 *
 * Only `jwt` is supported at the moment.
 *
 * @public
 */
declare type EncodingFormat = 'jwt';
/**
 * Encapsulates the parameters required to create a
 * {@link https://www.w3.org/TR/vc-data-model/#presentations | W3C Verifiable Presentation}
 *
 * @public
 */
interface ICreateVerifiablePresentationArgs {
    /**
     * The json payload of the Presentation according to the
     * {@link https://www.w3.org/TR/vc-data-model/#presentations | canonical model}.
     *
     * The signer of the Presentation is chosen based on the `holder` property
     * of the `presentation`
     *
     * '@context', 'type' and 'issuanceDate' will be added automatically if omitted
     */
    presentation: {
        id?: string;
        holder: string;
        issuanceDate?: string;
        expirationDate?: string;
        '@context'?: string[];
        type?: string[];
        verifier: string[];
        verifiableCredential: VerifiableCredential[];
        [x: string]: any;
    };
    /**
     * If this parameter is true, the resulting VerifiablePresentation is sent to the
     * {@link @veramo/core#IDataStore | storage plugin} to be saved
     */
    save?: boolean;
    /**
     * The desired format for the VerifiablePresentation to be created.
     * Currently, only JWT is supported
     */
    proofFormat: EncodingFormat;
    /**
     * Remove payload members during JWT-JSON transformation. Defaults to `true`.
     * See https://www.w3.org/TR/vc-data-model/#jwt-encoding
     */
    removeOriginalFields?: boolean;
}
/**
 * Encapsulates the parameters required to create a
 * {@link https://www.w3.org/TR/vc-data-model/#credentials | W3C Verifiable Credential}
 *
 * @public
 */
interface ICreateVerifiableCredentialArgs {
    /**
     * The json payload of the Credential according to the
     * {@link https://www.w3.org/TR/vc-data-model/#credentials | canonical model}
     *
     * The signer of the Credential is chosen based on the `issuer.id` property
     * of the `credential`
     *
     * '@context', 'type' and 'issuanceDate' will be added automatically if omitted
     */
    credential: {
        '@context'?: string[];
        id?: string;
        type?: string[];
        issuer: {
            id: string;
            [x: string]: any;
        };
        issuanceDate?: string;
        expirationDate?: string;
        credentialSubject: {
            id?: string;
            [x: string]: any;
        };
        credentialStatus?: {
            id: string;
            type: string;
        };
        [x: string]: any;
    };
    /**
     * If this parameter is true, the resulting VerifiablePresentation is sent to the
     * {@link @veramo/core#IDataStore | storage plugin} to be saved
     */
    save?: boolean;
    /**
     * The desired format for the VerifiablePresentation to be created.
     * Currently, only JWT is supported
     */
    proofFormat: EncodingFormat;
    /**
     * Remove payload members during JWT-JSON transformation. Defaults to `true`.
     * See https://www.w3.org/TR/vc-data-model/#jwt-encoding
     */
    removeOriginalFields?: boolean;
}
/**
 * The interface definition for a plugin that can generate Verifiable Credentials and Presentations
 *
 * @remarks Please see {@link https://www.w3.org/TR/vc-data-model | W3C Verifiable Credentials data model}
 *
 * @public
 */
interface ICredentialIssuer extends IPluginMethodMap {
    /**
     * Creates a Verifiable Presentation.
     * The payload, signer and format are chosen based on the `args` parameter.
     *
     * @param args - Arguments necessary to create the Presentation.
     * @param context - This reserved param is automatically added and handled by the framework, *do not override*
     *
     * @returns - a promise that resolves to the {@link @veramo/core#VerifiablePresentation} that was requested or rejects with an error
     * if there was a problem with the input or while getting the key to sign
     *
     * @remarks Please see {@link https://www.w3.org/TR/vc-data-model/#presentations | Verifiable Presentation data model }
     */
    createVerifiablePresentation(args: ICreateVerifiablePresentationArgs, context: IContext): Promise<VerifiablePresentation>;
    /**
     * Creates a Verifiable Credential.
     * The payload, signer and format are chosen based on the `args` parameter.
     *
     * @param args - Arguments necessary to create the Presentation.
     * @param context - This reserved param is automatically added and handled by the framework, *do not override*
     *
     * @returns - a promise that resolves to the {@link @veramo/core#VerifiableCredential} that was requested or rejects with an error
     * if there was a problem with the input or while getting the key to sign
     *
     * @remarks Please see {@link https://www.w3.org/TR/vc-data-model/#credentials | Verifiable Credential data model}
     */
    createVerifiableCredential(args: ICreateVerifiableCredentialArgs, context: IContext): Promise<VerifiableCredential>;
}
/**
 * Represents the requirements that this plugin has.
 * The agent that is using this plugin is expected to provide these methods.
 *
 * This interface can be used for static type checks, to make sure your application is properly initialized.
 */
declare type IContext = IAgentContext<IResolver & Pick<IDIDManager, 'didManagerGet'> & Pick<IDataStore, 'dataStoreSaveVerifiablePresentation' | 'dataStoreSaveVerifiableCredential'> & Pick<IKeyManager, 'keyManagerSignJWT'>>;

/**
 * Used for requesting Credentials using Selective Disclosure.
 * Represents an accepted issuer of a credential.
 *
 * @beta
 */
interface Issuer {
    /**
     * The DID of the issuer of a requested credential.
     */
    did: string;
    /**
     * A URL where a credential of that type can be obtained.
     */
    url: string;
}
/**
 * Represents the Selective Disclosure request parameters.
 *
 * @remarks See {@link https://github.com/uport-project/specs/blob/develop/messages/sharereq.md | Selective Disclosure Request}
 *
 * @beta
 */
interface ISelectiveDisclosureRequest {
    /**
     * The issuer of the request
     */
    issuer: string;
    /**
     * The target of the request
     */
    subject?: string;
    /**
     * The URL where the response should be sent back
     */
    replyUrl?: string;
    tag?: string;
    /**
     * A list of claims that are being requested
     */
    claims: ICredentialRequestInput[];
    /**
     * A list of issuer credentials that the target will use to establish trust
     */
    credentials?: string[];
}
/**
 * Describes a particular credential that is being requested
 *
 * @remarks See {@link https://github.com/uport-project/specs/blob/develop/messages/sharereq.md | Selective Disclosure Request}
 *
 * @beta
 */
interface ICredentialRequestInput {
    /**
     * Motive for requiring this credential.
     */
    reason?: string;
    /**
     * If it is essential. A response that does not include this credential is not sufficient.
     */
    essential?: boolean;
    /**
     * The credential type. See {@link https://www.w3.org/TR/vc-data-model/#types | W3C Credential Types}
     */
    credentialType?: string;
    /**
     * The credential context. See {@link https://www.w3.org/TR/vc-data-model/#contexts | W3C Credential Context}
     */
    credentialContext?: string;
    /**
     * The name of the claim property that the credential should express.
     */
    claimType: string;
    /**
     * The value of the claim that the credential should express.
     */
    claimValue?: string;
    /**
     * A list of accepted Issuers for this credential.
     */
    issuers?: Issuer[];
}
/**
 * The credentials that make up a response of a Selective Disclosure
 *
 * @remarks See {@link https://github.com/uport-project/specs/blob/develop/messages/sharereq.md | Selective Disclosure Request}
 *
 * @beta
 */
interface ICredentialsForSdr extends ICredentialRequestInput {
    credentials: VerifiableCredential[];
}
/**
 * The result of a selective disclosure response validation.
 *
 * @beta
 */
interface IPresentationValidationResult {
    valid: boolean;
    claims: ICredentialsForSdr[];
}
/**
 * Contains the parameters of a Selective Disclosure Request.
 *
 * @remarks See {@link https://github.com/uport-project/specs/blob/develop/messages/sharereq.md | Selective Disclosure Request}
 * specs
 *
 * @beta
 */
interface ICreateSelectiveDisclosureRequestArgs {
    data: ISelectiveDisclosureRequest;
}
/**
 * Encapsulates the params needed to gather credentials to fulfill a Selective disclosure request.
 *
 * @remarks See {@link https://github.com/uport-project/specs/blob/develop/messages/sharereq.md | Selective Disclosure Request}
 * specs
 *
 * @beta
 */
interface IGetVerifiableCredentialsForSdrArgs {
    /**
     * The Selective Disclosure Request (issuer is omitted)
     */
    sdr: Omit<ISelectiveDisclosureRequest, 'issuer'>;
    /**
     * The DID of the subject
     */
    did?: string;
}
/**
 * A tuple used to verify a Selective Disclosure Response.
 * Encapsulates the response(`presentation`) and the corresponding request (`sdr`) that made it.
 *
 * @beta
 */
interface IValidatePresentationAgainstSdrArgs {
    presentation: VerifiablePresentation;
    sdr: ISelectiveDisclosureRequest;
}
/**
 * Profile data
 *
 * @beta
 */
interface ICreateProfileCredentialsArgs {
    /**
     * Holder DID
     */
    holder: string;
    /**
     * Optional. Verifier DID
     */
    verifier?: string;
    /**
     * Optional. Name
     */
    name?: string;
    /**
     * Optional. Picture URL
     */
    picture?: string;
    /**
     * Optional. URL
     */
    url?: string;
    /**
     * Save presentation
     */
    save: boolean;
    /**
     * Send presentation
     */
    send: boolean;
}
/**
 * Describes the interface of a Selective Disclosure plugin.
 *
 * @remarks See {@link https://github.com/uport-project/specs/blob/develop/messages/sharereq.md | Selective Disclosure Request}
 *
 * @beta
 */
interface ISelectiveDisclosure extends IPluginMethodMap {
    createSelectiveDisclosureRequest(args: ICreateSelectiveDisclosureRequestArgs, context: IAgentContext<IDIDManager & IKeyManager>): Promise<string>;
    getVerifiableCredentialsForSdr(args: IGetVerifiableCredentialsForSdrArgs, context: IAgentContext<IDataStoreORM>): Promise<Array<ICredentialsForSdr>>;
    validatePresentationAgainstSdr(args: IValidatePresentationAgainstSdrArgs, context: IAgentContext<{}>): Promise<IPresentationValidationResult>;
    createProfilePresentation(args: ICreateProfileCredentialsArgs, context: IAgentContext<ICredentialIssuer & IDIDManager>): Promise<VerifiablePresentation>;
}

interface BaseDialogOptions {
    title?: string;
    message?: string;
    timeout?: number;
    allowCancel?: boolean;
}
interface TextOptions extends BaseDialogOptions {
    hiddenText?: boolean;
    default?: string;
}
interface ConfirmationOptions extends BaseDialogOptions {
    acceptMsg?: string;
    rejectMsg?: string;
}
interface SelectOptions<T> extends BaseDialogOptions {
    values: T[];
    getText?: (obj: T) => string;
    getContext?: (obj: T) => DialogOptionContext;
}
interface TextFormDescriptor extends TextOptions {
    type: 'text';
}
interface ConfirmationFormDescriptor extends ConfirmationOptions {
    type: 'confirmation';
}
interface SelectFormDescriptor<T> extends SelectOptions<T> {
    type: 'select';
}
type DialogOptionContext = 'success' | 'danger';
type Descriptors<T = any> = TextFormDescriptor | ConfirmationFormDescriptor | SelectFormDescriptor<T>;
type DescriptorsMap<T = any> = {
    [K in keyof Partial<T>]: Descriptors<T[K]>;
};
interface FormOptions<T> extends BaseDialogOptions {
    descriptors: DescriptorsMap<T>;
    order: Array<keyof T>;
}
type DialogResponse<T> = Promise<T | undefined>;
interface Dialog {
    text: (options: TextOptions) => DialogResponse<string>;
    confirmation: (options: ConfirmationOptions) => DialogResponse<boolean>;
    authenticate: () => DialogResponse<boolean>;
    select: <T>(options: SelectOptions<T>) => DialogResponse<T>;
    form: <T>(options: FormOptions<T>) => DialogResponse<T>;
}

interface KeyWallet<T extends TypedArray = Uint8Array> {
    createAccountKeyPair: () => Promise<string>;
    getPublicKey: (id: string) => Promise<KeyLike>;
    signDigest: (id: string, message: T) => Promise<T>;
    delete: (id: string) => Promise<boolean>;
    wipe: () => Promise<void>;
}

type PluginMap = IDIDManager & IKeyManager & IResolver & IMessageHandler & ISelectiveDisclosure & ICredentialIssuer;
interface ProviderData {
    network: string;
    rpcUrl?: string | string[];
    web3Provider?: object;
    ttl?: number;
    gas?: number;
    registry?: string;
}
declare class Veramo<T extends BaseWalletModel = BaseWalletModel> {
    agent: TAgent<PluginMap>;
    providers: Record<string, AbstractIdentifierProvider>;
    defaultKms: string;
    providersData: Record<string, ProviderData>;
    constructor(store: Store<T>, keyWallet: KeyWallet, providersData: Record<string, ProviderData>);
    getProvider(name: string): AbstractIdentifierProvider;
}

type CanBePromise<T> = Promise<T> | T;
type TypedArray = Int8Array | Uint8Array | Uint8ClampedArray | Int16Array | Uint16Array | Int32Array | Uint32Array | Float32Array | Float64Array | BigInt64Array | BigUint64Array;
type KeyLike = Uint8Array;

type Resource$1 = WalletComponents.Schemas.Resource & WalletComponents.Schemas.ResourceId & {
    identity?: WalletComponents.Schemas.ObjectResource['identity'];
} & {
    parentResource?: WalletComponents.Schemas.ObjectResource['parentResource'];
};
type Identity = IIdentifier;
interface BaseWalletModel {
    resources: {
        [id: string]: Resource$1;
    };
    identities: {
        [did: string]: Identity;
    };
}
interface Store<T extends Record<string, any> = Record<string, unknown>> {
    get<Key extends keyof T>(key: Key): CanBePromise<T[Key]>;
    get<Key extends keyof T>(key: Key, defaultValue: Required<T>[Key]): CanBePromise<Required<T>[Key]>;
    set(store: Partial<T>): CanBePromise<void>;
    set<Key extends keyof T>(key: Key, value: T[Key]): CanBePromise<void>;
    set(key: string, value: unknown): CanBePromise<void>;
    has<Key extends keyof T>(key: Key): CanBePromise<boolean>;
    has(key: string): CanBePromise<boolean>;
    delete<Key extends keyof T>(key: Key): CanBePromise<void>;
    delete(key: string): CanBePromise<void>;
    clear: () => CanBePromise<void>;
    getStore: () => CanBePromise<T>;
    getPath: () => string;
    on(eventName: 'changed', listener: (changedAt: number) => void): this;
    on(eventName: 'cleared', listener: (changedAt: number) => void): this;
    on(eventName: string | symbol, listener: (...args: any[]) => void): this;
    emit(eventName: 'changed', changedAt: number): boolean;
    emit(eventName: 'cleared', changedAt: number): boolean;
    emit(eventName: string | symbol, ...args: any[]): boolean;
}

type ToastType = 'info' | 'success' | 'warning' | 'error';
interface ToastOptions {
    message: string;
    type?: ToastType;
    details?: string;
    timeout?: number;
}
interface Toast {
    show: (toast: ToastOptions) => void;
    close: (toastId: string) => void;
}

interface Validation {
    validated: boolean;
    errors: Error[];
}
type Resource = WalletComponents.Schemas.Resource;
type Validator<T extends Resource> = (resource: T, veramo: Veramo) => Promise<Error[]>;
declare class ResourceValidator {
    protected validators: {
        [key: string]: Validator<any> | undefined;
    };
    constructor();
    private initValidators;
    private setValidator;
    validate(resource: Resource, veramo: Veramo): Promise<Validation>;
}

interface WalletFunctionMetadata {
    name: string;
    description?: string;
    call: string;
    scopes?: string[];
}

interface Wallet {
    call: (functionMetadata: WalletFunctionMetadata) => Promise<void>;
    getResources: () => Promise<BaseWalletModel['resources']>;
    getIdentities: () => Promise<BaseWalletModel['identities']>;
    deleteResource: (id: string) => Promise<void>;
    deleteIdentity: (did: string) => Promise<void>;
    wipe: () => Promise<void>;
    identityList(queryParameters: WalletPaths.IdentityList.QueryParameters): Promise<WalletPaths.IdentityList.Responses.$200>;
    identityCreate(requestBody: WalletPaths.IdentityCreate.RequestBody): Promise<WalletPaths.IdentityCreate.Responses.$201>;
    identitySelect(queryParameters: WalletPaths.IdentitySelect.QueryParameters): Promise<WalletPaths.IdentitySelect.Responses.$200>;
    identitySign(pathParameters: WalletPaths.IdentitySign.PathParameters, requestBody: WalletPaths.IdentitySign.RequestBody): Promise<WalletPaths.IdentitySign.Responses.$200>;
    identityInfo(pathParameters: WalletPaths.IdentityInfo.PathParameters): Promise<WalletPaths.IdentityInfo.Responses.$200>;
    identityDeployTransaction(pathParameters: WalletPaths.IdentityDeployTransaction.PathParameters, requestBody: WalletPaths.IdentityDeployTransaction.RequestBody): Promise<WalletPaths.IdentityDeployTransaction.Responses.$200>;
    resourceList(queryParameters: WalletPaths.ResourceList.QueryParameters): Promise<WalletPaths.ResourceList.Responses.$200>;
    resourceCreate(requestBody: WalletPaths.ResourceCreate.RequestBody): Promise<WalletPaths.ResourceCreate.Responses.$201>;
    selectiveDisclosure(pathParameters: WalletPaths.SelectiveDisclosure.PathParameters): Promise<WalletPaths.SelectiveDisclosure.Responses.$200>;
    transactionDeploy(requestBody: WalletPaths.TransactionDeploy.RequestBody): Promise<WalletPaths.TransactionDeploy.Responses.$200>;
    didJwtVerify(requestBody: WalletPaths.DidJwtVerify.RequestBody): Promise<WalletPaths.DidJwtVerify.Responses.$200>;
    providerinfoGet(): Promise<WalletPaths.ProviderinfoGet.Responses.$200>;
}

interface WalletOptionsCryptoWallet {
    keyWallet: KeyWallet;
}
interface WalletOptionsSettings<T extends BaseWalletModel> {
    dialog: Dialog;
    store: Store<T>;
    toast: Toast;
    provider?: string;
    providersData?: Record<string, ProviderData>;
}
type WalletOptions<T extends BaseWalletModel> = WalletOptionsSettings<T> & WalletOptionsCryptoWallet;

interface SelectIdentityOptions {
    reason?: string;
}
interface TransactionOptions {
    transaction?: string;
    notifyUser?: boolean;
}
type ResourceMap = BaseWalletModel['resources'];
declare class BaseWallet<Options extends WalletOptions<Model>, Model extends BaseWalletModel = BaseWalletModel> implements Wallet {
    dialog: Dialog;
    store: Store<Model>;
    toast: Toast;
    veramo: Veramo<Model>;
    protected keyWallet: KeyWallet;
    protected resourceValidator: ResourceValidator;
    protected provider: string;
    protected providersData: Record<string, ProviderData>;
    constructor(opts: Options);
    executeTransaction(options?: TransactionOptions): Promise<void>;
    queryBalance(): Promise<void>;
    createTransaction(): Promise<void>;
    wipe(): Promise<void>;
    selectIdentity(options?: SelectIdentityOptions): Promise<Identity>;
    selectCredentialsForSdr(sdrMessage: IMessage): Promise<VerifiablePresentation | undefined>;
    getKeyWallet<T extends KeyWallet>(): T;
    call(functionMetadata: WalletFunctionMetadata): Promise<void>;
    getIdentities(): Promise<BaseWalletModel['identities']>;
    identityList(queryParameters: WalletPaths.IdentityList.QueryParameters): Promise<WalletPaths.IdentityList.Responses.$200>;
    identityCreate(requestBody: WalletPaths.IdentityCreate.RequestBody): Promise<WalletPaths.IdentityCreate.Responses.$201>;
    identitySelect(queryParameters: WalletPaths.IdentitySelect.QueryParameters): Promise<WalletPaths.IdentitySelect.Responses.$200>;
    identitySign(pathParameters: WalletPaths.IdentitySign.PathParameters, requestBody: WalletPaths.IdentitySign.RequestBody): Promise<WalletPaths.IdentitySign.Responses.$200>;
    identityInfo(pathParameters: WalletPaths.IdentityInfo.PathParameters): Promise<WalletPaths.IdentityInfo.Responses.$200>;
    identityDeployTransaction(pathParameters: WalletPaths.IdentityDeployTransaction.PathParameters, requestBody: WalletComponents.Schemas.Transaction): Promise<WalletComponents.Schemas.Receipt>;
    getResources(): Promise<ResourceMap>;
    private getResource;
    private setResource;
    resourceList(query: WalletPaths.ResourceList.QueryParameters): Promise<WalletPaths.ResourceList.Responses.$200>;
    deleteResource(id: string, requestConfirmation?: boolean): Promise<void>;
    deleteIdentity(did: string): Promise<void>;
    resourceCreate(requestBody: WalletPaths.ResourceCreate.RequestBody): Promise<WalletPaths.ResourceCreate.Responses.$201>;
    selectiveDisclosure(pathParameters: WalletPaths.SelectiveDisclosure.PathParameters): Promise<WalletPaths.SelectiveDisclosure.Responses.$200>;
    transactionDeploy(requestBody: WalletComponents.Schemas.SignedTransaction): Promise<WalletPaths.TransactionDeploy.Responses.$200>;
    didJwtVerify(requestBody: WalletPaths.DidJwtVerify.RequestBody): Promise<WalletPaths.DidJwtVerify.Responses.$200>;
    providerinfoGet(): Promise<WalletPaths.ProviderinfoGet.Responses.$200>;
}

declare class FileStore<T extends Record<string, any> = Record<string, unknown>> extends EventEmitter$1 implements Store<T> {
    filepath: string;
    private key;
    private readonly _password?;
    private _passwordSalt?;
    initialized: Promise<void>;
    defaultModel: T;
    constructor(filepath: string, keyObject?: KeyObject, defaultModel?: T);
    constructor(filepath: string, password?: string, defaultModel?: T);
    on(eventName: 'changed', listener: (changedAt: number) => void): this;
    on(eventName: 'cleared', listener: (changedAt: number) => void): this;
    on(eventName: string | symbol, listener: (...args: any[]) => void): this;
    emit(eventName: 'changed', changedAt: number): boolean;
    emit(eventName: 'cleared', changedAt: number): boolean;
    emit(eventName: string | symbol, ...args: any[]): boolean;
    private init;
    deriveKey(password: string, salt?: Buffer): Promise<void>;
    private getModel;
    private setModel;
    private encryptModel;
    private decryptModel;
    get(key: any, defaultValue?: any): Promise<any>;
    set(keyOrStore: any, value?: any): Promise<void>;
    has(key: any): Promise<boolean>;
    delete(key: any): Promise<void>;
    clear(): Promise<void>;
    getStore(): Promise<T>;
    getPath(): string;
}

interface Values {
    text: string | undefined;
    confirmation: boolean | undefined;
    selectMap: <T>(values: T[]) => T | undefined;
}
declare class NullDialog implements Dialog {
    private readonly valuesStack;
    get values(): Values;
    setValues(values: Partial<Values>, cb: () => Promise<void>): Promise<void>;
    text(options: TextOptions): DialogResponse<string>;
    confirmation(options: ConfirmationOptions): DialogResponse<boolean>;
    select<T>(options: SelectOptions<T>): DialogResponse<T>;
    authenticate(): DialogResponse<boolean>;
    form<T>(options: FormOptions<T>): DialogResponse<T>;
}

declare class ConsoleToast implements Toast {
    show(toast: ToastOptions): void;
    close(toastId: string): void;
}

type KeyType = 'Secp256k1';
interface Key {
    kid: string;
    type: KeyType;
    publicKeyHex: string;
    privateKeyHex: string;
}
interface BokWalletModel extends BaseWalletModel {
    keys: {
        [kid: string]: Key;
    };
}

interface ImportInfo {
    alias: string;
    privateKey: string;
}
declare class BokWallet extends BaseWallet<WalletOptions<BokWalletModel>> {
    importDid(importInfo?: ImportInfo): Promise<void>;
}

interface ServerWallet extends BokWallet {
    dialog: NullDialog;
    store: FileStore<BokWalletModel>;
    toast: ConsoleToast;
}

declare class I3mServerWalletAgent extends EthersIoAgent {
    wallet: ServerWallet;
    did: string;
    constructor(serverWallet: ServerWallet, did: string, dltConfig?: Partial<Omit<DltConfig, 'rpcProviderUrk'>>);
}

declare class I3mServerWalletAgentDest extends I3mServerWalletAgent implements NrpDltAgentDest {
    getSecretFromLedger(secretLength: number, signerAddress: string, exchangeId: string, timeout: number): Promise<{
        hex: string;
        iat: number;
    }>;
}

interface NrpDltAgentOrig extends NrpDltAgent {
    deploySecret: (secretHex: string, exchangeId: string) => Promise<string>;
    getAddress: () => Promise<string>;
    nextNonce: () => Promise<number>;
}

declare class EthersIoAgentOrig extends EthersIoAgent implements NrpDltAgentOrig {
    signer: ethers.Wallet;
    count: number;
    constructor(dltConfig: Partial<DltConfig> & Pick<DltConfig, 'rpcProviderUrl'>, privateKey?: string | Uint8Array);
    deploySecret(secretHex: string, exchangeId: string): Promise<string>;
    getAddress(): Promise<string>;
    nextNonce(): Promise<number>;
}

declare class I3mWalletAgentOrig extends I3mWalletAgent implements NrpDltAgentOrig {
    count: number;
    deploySecret(secretHex: string, exchangeId: string): Promise<string>;
    getAddress(): Promise<string>;
    nextNonce(): Promise<number>;
}

declare class I3mServerWalletAgentOrig extends I3mServerWalletAgent implements NrpDltAgentOrig {
    count: number;
    deploySecret(secretHex: string, exchangeId: string): Promise<string>;
    getAddress(): Promise<string>;
    nextNonce(): Promise<number>;
}

//# sourceMappingURL=index.d.ts.map

type index_d$2_EthersIoAgentDest = EthersIoAgentDest;
declare const index_d$2_EthersIoAgentDest: typeof EthersIoAgentDest;
type index_d$2_EthersIoAgentOrig = EthersIoAgentOrig;
declare const index_d$2_EthersIoAgentOrig: typeof EthersIoAgentOrig;
type index_d$2_I3mServerWalletAgentDest = I3mServerWalletAgentDest;
declare const index_d$2_I3mServerWalletAgentDest: typeof I3mServerWalletAgentDest;
type index_d$2_I3mServerWalletAgentOrig = I3mServerWalletAgentOrig;
declare const index_d$2_I3mServerWalletAgentOrig: typeof I3mServerWalletAgentOrig;
type index_d$2_I3mWalletAgentDest = I3mWalletAgentDest;
declare const index_d$2_I3mWalletAgentDest: typeof I3mWalletAgentDest;
type index_d$2_I3mWalletAgentOrig = I3mWalletAgentOrig;
declare const index_d$2_I3mWalletAgentOrig: typeof I3mWalletAgentOrig;
type index_d$2_NrpDltAgentDest = NrpDltAgentDest;
type index_d$2_NrpDltAgentOrig = NrpDltAgentOrig;
declare namespace index_d$2 {
  export {
    index_d$2_EthersIoAgentDest as EthersIoAgentDest,
    index_d$2_EthersIoAgentOrig as EthersIoAgentOrig,
    index_d$2_I3mServerWalletAgentDest as I3mServerWalletAgentDest,
    index_d$2_I3mServerWalletAgentOrig as I3mServerWalletAgentOrig,
    index_d$2_I3mWalletAgentDest as I3mWalletAgentDest,
    index_d$2_I3mWalletAgentOrig as I3mWalletAgentOrig,
    index_d$2_NrpDltAgentDest as NrpDltAgentDest,
    index_d$2_NrpDltAgentOrig as NrpDltAgentOrig,
  };
}

declare function checkCompleteness(verificationRequest: string, wallet: NrpDltAgentDest, connectionTimeout?: number): Promise<{
    vrPayload: VerificationRequestPayload;
    porPayload: PoRPayload;
    pooPayload: PoOPayload;
    destPublicJwk: JWK;
    origPublicJwk: JWK;
}>;

declare function checkDecryption(disputeRequest: string, wallet: NrpDltAgentDest): Promise<{
    drPayload: DisputeRequestPayload;
    porPayload: PoRPayload;
    pooPayload: PoOPayload;
    destPublicJwk: JWK;
    origPublicJwk: JWK;
}>;

declare class ConflictResolver {
    jwkPair: JwkPair;
    dltAgent: NrpDltAgentDest;
    private readonly initialized;
    constructor(jwkPair: JwkPair, dltAgent: NrpDltAgentDest);
    private init;
    resolveCompleteness(verificationRequest: string): Promise<string>;
    resolveDispute(disputeRequest: string): Promise<string>;
    private _resolution;
}

declare function generateVerificationRequest(iss: 'orig' | 'dest', dataExchangeId: string, por: string, privateJwk: JWK): Promise<string>;

declare function verifyPor(por: string, wallet: NrpDltAgentDest, connectionTimeout?: number): Promise<{
    porPayload: PoRPayload;
    pooPayload: PoOPayload;
    secretHex: string;
    destPublicJwk: JWK;
    origPublicJwk: JWK;
}>;

declare function verifyResolution<T extends ResolutionPayload>(resolution: string, pubJwk?: JWK): Promise<DecodedProof<T>>;

//# sourceMappingURL=index.d.ts.map

type index_d$1_ConflictResolver = ConflictResolver;
declare const index_d$1_ConflictResolver: typeof ConflictResolver;
declare const index_d$1_checkCompleteness: typeof checkCompleteness;
declare const index_d$1_checkDecryption: typeof checkDecryption;
declare const index_d$1_generateVerificationRequest: typeof generateVerificationRequest;
declare const index_d$1_verifyPor: typeof verifyPor;
declare const index_d$1_verifyResolution: typeof verifyResolution;
declare namespace index_d$1 {
  export {
    index_d$1_ConflictResolver as ConflictResolver,
    index_d$1_checkCompleteness as checkCompleteness,
    index_d$1_checkDecryption as checkDecryption,
    index_d$1_generateVerificationRequest as generateVerificationRequest,
    index_d$1_verifyPor as verifyPor,
    index_d$1_verifyResolution as verifyResolution,
  };
}

declare function generateKeys(alg: SigningAlg, privateKey?: Uint8Array | string, base64?: boolean): Promise<JwkPair>;

declare function importJwk(jwk: JWK, alg?: string): Promise<KeyLike$1 | Uint8Array>;

declare function jweEncrypt(block: Uint8Array, secretOrPublicKey: JWK, encAlg?: EncryptionAlg): Promise<string>;
declare function jweDecrypt(jwe: string, secretOrPrivateKey: JWK): Promise<CompactDecryptResult>;

declare function jwsDecode<T extends ProofPayload>(jws: string, publicJwk?: JWK | getFromJws<T>): Promise<DecodedProof<T>>;

declare function oneTimeSecret(encAlg: EncryptionAlg, secret?: Uint8Array | string, base64?: boolean): Promise<Exclude<Block['secret'], undefined>>;

declare function verifyKeyPair(pubJWK: JWK, privJWK: JWK): Promise<void>;

declare class NonRepudiationDest {
    agreement: DataExchangeAgreement;
    exchange?: DataExchange;
    jwkPairDest: JwkPair;
    publicJwkOrig: JWK;
    block: Block;
    dltAgent: NrpDltAgentDest;
    readonly initialized: Promise<boolean>;
    constructor(agreement: DataExchangeAgreement, privateJwk: JWK, dltAgent: NrpDltAgentDest);
    private asyncConstructor;
    verifyPoO(poo: string, cipherblock: string, options?: Pick<TimestampVerifyOptions, 'timestamp' | 'tolerance'>): Promise<DecodedProof<PoOPayload>>;
    generatePoR(): Promise<StoredProof<PoRPayload>>;
    verifyPoP(pop: string, options?: Pick<TimestampVerifyOptions, 'timestamp' | 'tolerance'>): Promise<DecodedProof<PoPPayload>>;
    getSecretFromLedger(): Promise<{
        hex: string;
        jwk: JWK;
    }>;
    decrypt(): Promise<Uint8Array>;
    generateVerificationRequest(): Promise<string>;
    generateDisputeRequest(): Promise<string>;
}

declare class NonRepudiationOrig {
    agreement: DataExchangeAgreement;
    exchange: DataExchange;
    jwkPairOrig: JwkPair;
    publicJwkDest: JWK;
    block: OrigBlock;
    dltAgent: NrpDltAgentOrig;
    readonly initialized: Promise<boolean>;
    constructor(agreement: DataExchangeAgreement, privateJwk: JWK, block: Uint8Array, dltAgent: NrpDltAgentOrig);
    private init;
    private _dltSetup;
    generatePoO(): Promise<StoredProof<PoOPayload>>;
    verifyPoR(por: string, options?: Pick<TimestampVerifyOptions, 'timestamp' | 'tolerance'>): Promise<StoredProof<PoRPayload>>;
    generatePoP(): Promise<StoredProof<PoPPayload>>;
    generateVerificationRequest(): Promise<string>;
}

//# sourceMappingURL=index.d.ts.map

type index_d_NonRepudiationDest = NonRepudiationDest;
declare const index_d_NonRepudiationDest: typeof NonRepudiationDest;
type index_d_NonRepudiationOrig = NonRepudiationOrig;
declare const index_d_NonRepudiationOrig: typeof NonRepudiationOrig;
declare namespace index_d {
  export {
    index_d_NonRepudiationDest as NonRepudiationDest,
    index_d_NonRepudiationOrig as NonRepudiationOrig,
  };
}

declare class NrError extends Error {
    nrErrors: NrErrorName[];
    constructor(error: any, nrErrors: NrErrorName[]);
    add(...nrErrors: NrErrorName[]): void;
}

declare function createProof<T extends NrProofPayload>(payload: Omit<T, 'iat'>, privateJwk: JWK): Promise<StoredProof<T>>;

declare function verifyProof<T extends NrProofPayload>(proof: string, expectedPayloadClaims: Partial<T> & {
    iss: T['iss'];
    proofType: T['proofType'];
    exchange: Dict<T['exchange']>;
}, options?: TimestampVerifyOptions): Promise<DecodedProof<T>>;

declare function checkTimestamp(timestamp: number, notBefore: number, notAfter: number, tolerance?: number): void;

declare function jsonSort(obj: any): any;

declare function parseHex(a: string, prefix0x?: boolean, byteLength?: number): string;

declare function parseJwk(jwk: JWK, stringify: true): Promise<string>;
declare function parseJwk(jwk: JWK, stringify: false): Promise<JWK>;

declare function sha(input: string | Uint8Array, algorithm: HashAlg): Promise<Uint8Array>;

declare function parseAddress(a: string): string;

declare function getDltAddress(didOrKeyInHex: string): string;

declare function exchangeId(exchange: Omit<DataExchange, 'id'>): Promise<string>;

declare function validateDataSharingAgreementSchema(agreement: DataSharingAgreement): Promise<Error[]>;
declare function validateDataExchange(dataExchange: DataExchange): Promise<Error[]>;
declare function validateDataExchangeAgreement(agreement: DataExchangeAgreement): Promise<NrError[]>;

export { Algs, Block, index_d$1 as ConflictResolution, ConflictResolutionRequestPayload, ContractConfig, DataExchange, DataExchangeAgreement, DataSharingAgreement, DecodedProof, Dict, DisputeRequestPayload, DisputeResolutionPayload, DltConfig, ENC_ALGS, EncryptionAlg, EthersIoAgentDest, EthersIoAgentOrig, HASH_ALGS, HashAlg, I3mServerWalletAgentDest, I3mServerWalletAgentOrig, I3mWalletAgentDest, I3mWalletAgentOrig, JWK, JwkPair, KEY_AGREEMENT_ALGS, index_d as NonRepudiationProtocol, NrError, NrErrorName, NrProofPayload, NrpDltAgentDest, NrpDltAgentOrig, OrigBlock, PoOPayload, PoPPayload, PoRPayload, ProofPayload, ResolutionPayload, SIGNING_ALGS, index_d$2 as Signers, SigningAlg, StoredProof, TimestampVerifyOptions, VerificationRequestPayload, VerificationResolutionPayload, checkTimestamp, createProof, defaultDltConfig, exchangeId, generateKeys, getDltAddress, getFromJws, importJwk, jsonSort, jweDecrypt, jweEncrypt, jwsDecode, oneTimeSecret, parseAddress, parseHex, parseJwk, sha, validateDataExchange, validateDataExchangeAgreement, validateDataSharingAgreementSchema, verifyKeyPair, verifyProof };
