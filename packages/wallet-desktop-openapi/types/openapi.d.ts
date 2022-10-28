/* eslint-disable @typescript-eslint/no-empty-interface */
export namespace WalletComponents {
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
      parentResource?: string
      /**
             * DID
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      identity?: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
      resource: {
        dataOfferingDescription: {
          dataOfferingId: string
          version: number
          category?: string
          active: boolean
          title?: string
        }
        parties: {
          /**
                     * DID
                     * example:
                     * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                     */
          providerDid: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
          /**
                     * DID
                     * example:
                     * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                     */
          consumerDid: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
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
        dataExchangeAgreement: {
          orig: string
          dest: string
          encAlg: string
          signingAlg: string
          hashAlg: string
          /**
                     * Ethereum Address
                     * example:
                     * 0x71C7656EC7ab88b098defB751B7401B5f6d8976F
                     */
          ledgerContractAddress: string // ^0x([0-9A-Fa-f]){40}$
          /**
                     * Ethereum Address
                     * example:
                     * 0x71C7656EC7ab88b098defB751B7401B5f6d8976F
                     */
          ledgerSignerAddress: string // ^0x([0-9A-Fa-f]){40}$
          pooToPorDelay: number
          pooToPopDelay: number
          pooToSecretDelay: number
        }
        signatures: {
          /**
                     * CompactJWS
                     */
          providerSignature: string // ^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$
          /**
                     * CompactJWS
                     */
          consumerSignature: string // ^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$
        }
      }
    }
    export interface DataExchangeAgreement {
      orig: string
      dest: string
      encAlg: string
      signingAlg: string
      hashAlg: string
      /**
             * Ethereum Address
             * example:
             * 0x71C7656EC7ab88b098defB751B7401B5f6d8976F
             */
      ledgerContractAddress: string // ^0x([0-9A-Fa-f]){40}$
      /**
             * Ethereum Address
             * example:
             * 0x71C7656EC7ab88b098defB751B7401B5f6d8976F
             */
      ledgerSignerAddress: string // ^0x([0-9A-Fa-f]){40}$
      pooToPorDelay: number
      pooToPopDelay: number
      pooToSecretDelay: number
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
        /**
                 * DID
                 * example:
                 * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                 */
        providerDid: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
        /**
                 * DID
                 * example:
                 * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                 */
        consumerDid: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
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
      dataExchangeAgreement: {
        orig: string
        dest: string
        encAlg: string
        signingAlg: string
        hashAlg: string
        /**
                 * Ethereum Address
                 * example:
                 * 0x71C7656EC7ab88b098defB751B7401B5f6d8976F
                 */
        ledgerContractAddress: string // ^0x([0-9A-Fa-f]){40}$
        /**
                 * Ethereum Address
                 * example:
                 * 0x71C7656EC7ab88b098defB751B7401B5f6d8976F
                 */
        ledgerSignerAddress: string // ^0x([0-9A-Fa-f]){40}$
        pooToPorDelay: number
        pooToPopDelay: number
        pooToSecretDelay: number
      }
      signatures: {
        /**
                 * CompactJWS
                 */
        providerSignature: string // ^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$
        /**
                 * CompactJWS
                 */
        consumerSignature: string // ^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$
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
        /**
                 * DID
                 * example:
                 * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                 */
        iss: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
      }
      signature: string // ^[A-Za-z0-9_-]+$
      /**
             * <base64url(header)>.<base64url(payload)>
             */
      data: string // ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$
    }
    /**
         * DID
         * example:
         * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
         */
    export type Did = string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
    /**
         * Ethereum Address
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
      /**
             * DID
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      did: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
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
      addresses?: string /* ^0x([0-9A-Fa-f]){40}$ */[]
    }
    /**
         * IdentityListInput
         * A list of DIDs
         */
    export type IdentityListInput = Array<{
      /**
             * DID
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      did: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
    }>
    /**
         * IdentitySelectOutput
         */
    export interface IdentitySelectOutput {
      /**
             * DID
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      did: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
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
      parentResource?: string
      /**
             * DID
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      identity?: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
      resource: string // ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$
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
      /**
             * DID
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      identity?: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
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
      /**
             * example:
             * http://95.211.3.250:8545
             */
      rpcUrl?: string
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
    export type Resource = /* Resource */ {
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
      parentResource?: string
      /**
             * DID
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      identity?: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
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
          /**
                     * DID
                     * example:
                     * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                     */
          id: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
        }
        /**
                 * example:
                 * 2021-06-10T19:07:28.000Z
                 */
        issuanceDate: string // date-time
        credentialSubject: {
          [name: string]: any
          /**
                     * DID
                     * example:
                     * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                     */
          id: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
        }
        proof: {
          [name: string]: any
          type: 'JwtProof2020'
        }
      }
    } | {
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
      /**
             * DID
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      identity?: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
      resource: {
        [name: string]: any
      }
    } | {
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
      parentResource?: string
      /**
             * DID
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      identity?: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
      resource: {
        dataOfferingDescription: {
          dataOfferingId: string
          version: number
          category?: string
          active: boolean
          title?: string
        }
        parties: {
          /**
                     * DID
                     * example:
                     * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                     */
          providerDid: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
          /**
                     * DID
                     * example:
                     * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                     */
          consumerDid: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
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
        dataExchangeAgreement: {
          orig: string
          dest: string
          encAlg: string
          signingAlg: string
          hashAlg: string
          /**
                     * Ethereum Address
                     * example:
                     * 0x71C7656EC7ab88b098defB751B7401B5f6d8976F
                     */
          ledgerContractAddress: string // ^0x([0-9A-Fa-f]){40}$
          /**
                     * Ethereum Address
                     * example:
                     * 0x71C7656EC7ab88b098defB751B7401B5f6d8976F
                     */
          ledgerSignerAddress: string // ^0x([0-9A-Fa-f]){40}$
          pooToPorDelay: number
          pooToPopDelay: number
          pooToSecretDelay: number
        }
        signatures: {
          /**
                     * CompactJWS
                     */
          providerSignature: string // ^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$
          /**
                     * CompactJWS
                     */
          consumerSignature: string // ^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$
        }
      }
    } | {
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
      parentResource?: string
      /**
             * DID
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      identity?: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
      resource: string // ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$
    }
    export interface ResourceId {
      id: string
    }
    /**
         * ResourceListOutput
         * A list of resources
         */
    export type ResourceListOutput = /* Resource */ Array<{
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
      parentResource?: string
      /**
             * DID
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      identity?: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
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
          /**
                     * DID
                     * example:
                     * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                     */
          id: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
        }
        /**
                 * example:
                 * 2021-06-10T19:07:28.000Z
                 */
        issuanceDate: string // date-time
        credentialSubject: {
          [name: string]: any
          /**
                     * DID
                     * example:
                     * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                     */
          id: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
        }
        proof: {
          [name: string]: any
          type: 'JwtProof2020'
        }
      }
    } | {
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
      /**
             * DID
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      identity?: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
      resource: {
        [name: string]: any
      }
    } | {
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
      parentResource?: string
      /**
             * DID
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      identity?: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
      resource: {
        dataOfferingDescription: {
          dataOfferingId: string
          version: number
          category?: string
          active: boolean
          title?: string
        }
        parties: {
          /**
                     * DID
                     * example:
                     * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                     */
          providerDid: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
          /**
                     * DID
                     * example:
                     * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                     */
          consumerDid: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
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
        dataExchangeAgreement: {
          orig: string
          dest: string
          encAlg: string
          signingAlg: string
          hashAlg: string
          /**
                     * Ethereum Address
                     * example:
                     * 0x71C7656EC7ab88b098defB751B7401B5f6d8976F
                     */
          ledgerContractAddress: string // ^0x([0-9A-Fa-f]){40}$
          /**
                     * Ethereum Address
                     * example:
                     * 0x71C7656EC7ab88b098defB751B7401B5f6d8976F
                     */
          ledgerSignerAddress: string // ^0x([0-9A-Fa-f]){40}$
          pooToPorDelay: number
          pooToPopDelay: number
          pooToSecretDelay: number
        }
        signatures: {
          /**
                     * CompactJWS
                     */
          providerSignature: string // ^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$
          /**
                     * CompactJWS
                     */
          consumerSignature: string // ^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$
        }
      }
    } | {
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
      parentResource?: string
      /**
             * DID
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      identity?: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
      resource: string // ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$
    }>
    export type ResourceType = 'VerifiableCredential' | 'Object' | 'Contract' | 'NonRepudiationProof'
    /**
         * SignInput
         */
    export type SignInput = /* SignInput */ {
      type: 'Transaction'
      /**
             * Transaction
             */
      data: {
        [name: string]: any
        from?: string
        to?: string
        nonce?: number
      }
    } | {
      type: 'Raw'
      data: {
        /**
                 * Base64Url encoded data to sign
                 */
        payload: string // ^[A-Za-z0-9_-]+$
      }
    } | {
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
      /**
             * Transaction
             */
      data: {
        [name: string]: any
        from?: string
        to?: string
        nonce?: number
      }
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
      parentResource?: string
      /**
             * DID
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      identity?: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
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
          /**
                     * DID
                     * example:
                     * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                     */
          id: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
        }
        /**
                 * example:
                 * 2021-06-10T19:07:28.000Z
                 */
        issuanceDate: string // date-time
        credentialSubject: {
          [name: string]: any
          /**
                     * DID
                     * example:
                     * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                     */
          id: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
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
export namespace WalletPaths {
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
      /**
             * VerificationOutput
             */
      export interface $200 {
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
      /**
             * Error
             */
      export interface Default {
        code: number // int32
        message: string
      }
    }
  }
  export namespace IdentityCreate {
    /**
         * IdentityCreateInput
         * Besides the here defined options, provider specific properties should be added here if necessary, e.g. "path" for BIP21 wallets, or the key algorithm (if the wallet supports multiple algorithm).
         *
         */
    export interface RequestBody {
      [name: string]: any
      alias?: string
    }
    export namespace Responses {
      /**
             * IdentityCreateOutput
             * It returns the account id and type
             *
             */
      export interface $201 {
        [name: string]: any
        /**
                 * DID
                 * example:
                 * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                 */
        did: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
      }
      /**
             * Error
             */
      export interface Default {
        code: number // int32
        message: string
      }
    }
  }
  export namespace IdentityDeployTransaction {
    export namespace Parameters {
      /**
             * DID
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      export type Did = string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
    }
    export interface PathParameters {
      did: /**
             * DID
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      Parameters.Did /* ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$ */
    }
    /**
         * Transaction
         */
    export interface RequestBody {
      [name: string]: any
      from?: string
      to?: string
      nonce?: number
    }
    export namespace Responses {
      /**
             * Receipt
             */
      export interface $200 {
        receipt: string
      }
    }
  }
  export namespace IdentityInfo {
    export namespace Parameters {
      /**
             * DID
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      export type Did = string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
    }
    export interface PathParameters {
      did: /**
             * DID
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      Parameters.Did /* ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$ */
    }
    export namespace Responses {
      /**
             * Identity Data
             */
      export interface $200 {
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
        addresses?: string /* ^0x([0-9A-Fa-f]){40}$ */[]
      }
      /**
             * Error
             */
      export interface Default {
        code: number // int32
        message: string
      }
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
      /**
             * IdentityListInput
             * A list of DIDs
             */
      export type $200 = Array<{
        /**
                 * DID
                 * example:
                 * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                 */
        did: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
      }>
      /**
             * Error
             */
      export interface Default {
        code: number // int32
        message: string
      }
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
      /**
             * IdentitySelectOutput
             */
      export interface $200 {
        /**
                 * DID
                 * example:
                 * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                 */
        did: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
      }
    }
  }
  export namespace IdentitySign {
    export namespace Parameters {
      /**
             * DID
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      export type Did = string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
    }
    export interface PathParameters {
      did: /**
             * DID
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      Parameters.Did /* ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$ */
    }
    /**
         * SignInput
         */
    export type RequestBody = /* SignInput */ {
      type: 'Transaction'
      /**
             * Transaction
             */
      data: {
        [name: string]: any
        from?: string
        to?: string
        nonce?: number
      }
    } | {
      type: 'Raw'
      data: {
        /**
                 * Base64Url encoded data to sign
                 */
        payload: string // ^[A-Za-z0-9_-]+$
      }
    } | {
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
    export namespace Responses {
      /**
             * SignOutput
             */
      export interface $200 {
        signature: string
      }
    }
  }
  export namespace ProviderinfoGet {
    export namespace Responses {
      /**
             * ProviderData
             * A JSON object with information of the DLT provider currently in use.
             */
      export interface $200 {
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
        /**
                 * example:
                 * http://95.211.3.250:8545
                 */
        rpcUrl?: string
      }
      /**
             * Error
             */
      export interface Default {
        code: number // int32
        message: string
      }
    }
  }
  export namespace ResourceCreate {
    /**
         * Resource
         */
    export type RequestBody = /* Resource */ {
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
      parentResource?: string
      /**
             * DID
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      identity?: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
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
          /**
                     * DID
                     * example:
                     * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                     */
          id: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
        }
        /**
                 * example:
                 * 2021-06-10T19:07:28.000Z
                 */
        issuanceDate: string // date-time
        credentialSubject: {
          [name: string]: any
          /**
                     * DID
                     * example:
                     * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                     */
          id: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
        }
        proof: {
          [name: string]: any
          type: 'JwtProof2020'
        }
      }
    } | {
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
      /**
             * DID
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      identity?: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
      resource: {
        [name: string]: any
      }
    } | {
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
      parentResource?: string
      /**
             * DID
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      identity?: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
      resource: {
        dataOfferingDescription: {
          dataOfferingId: string
          version: number
          category?: string
          active: boolean
          title?: string
        }
        parties: {
          /**
                     * DID
                     * example:
                     * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                     */
          providerDid: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
          /**
                     * DID
                     * example:
                     * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                     */
          consumerDid: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
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
        dataExchangeAgreement: {
          orig: string
          dest: string
          encAlg: string
          signingAlg: string
          hashAlg: string
          /**
                     * Ethereum Address
                     * example:
                     * 0x71C7656EC7ab88b098defB751B7401B5f6d8976F
                     */
          ledgerContractAddress: string // ^0x([0-9A-Fa-f]){40}$
          /**
                     * Ethereum Address
                     * example:
                     * 0x71C7656EC7ab88b098defB751B7401B5f6d8976F
                     */
          ledgerSignerAddress: string // ^0x([0-9A-Fa-f]){40}$
          pooToPorDelay: number
          pooToPopDelay: number
          pooToSecretDelay: number
        }
        signatures: {
          /**
                     * CompactJWS
                     */
          providerSignature: string // ^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$
          /**
                     * CompactJWS
                     */
          consumerSignature: string // ^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$
        }
      }
    } | {
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
      parentResource?: string
      /**
             * DID
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      identity?: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
      resource: string // ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$
    }
    export namespace Responses {
      export interface $201 {
        id: string
      }
      /**
             * Error
             */
      export interface Default {
        code: number // int32
        message: string
      }
    }
  }
  export namespace ResourceList {
    export namespace Parameters {
      /**
             * DID
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      export type Identity = string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
      export type Type = 'VerifiableCredential' | 'Object' | 'Contract' | 'NonRepudiationProof'
    }
    export interface QueryParameters {
      type?: Parameters.Type
      identity?: /**
             * DID
             * example:
             * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      Parameters.Identity /* ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$ */
    }
    export namespace Responses {
      /**
             * ResourceListOutput
             * A list of resources
             */
      export type $200 = /* Resource */ Array<{
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
        parentResource?: string
        /**
                 * DID
                 * example:
                 * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                 */
        identity?: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
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
            /**
                         * DID
                         * example:
                         * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                         */
            id: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
          }
          /**
                     * example:
                     * 2021-06-10T19:07:28.000Z
                     */
          issuanceDate: string // date-time
          credentialSubject: {
            [name: string]: any
            /**
                         * DID
                         * example:
                         * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                         */
            id: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
          }
          proof: {
            [name: string]: any
            type: 'JwtProof2020'
          }
        }
      } | {
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
        /**
                 * DID
                 * example:
                 * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                 */
        identity?: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
        resource: {
          [name: string]: any
        }
      } | {
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
        parentResource?: string
        /**
                 * DID
                 * example:
                 * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                 */
        identity?: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
        resource: {
          dataOfferingDescription: {
            dataOfferingId: string
            version: number
            category?: string
            active: boolean
            title?: string
          }
          parties: {
            /**
                         * DID
                         * example:
                         * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                         */
            providerDid: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
            /**
                         * DID
                         * example:
                         * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                         */
            consumerDid: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
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
          dataExchangeAgreement: {
            orig: string
            dest: string
            encAlg: string
            signingAlg: string
            hashAlg: string
            /**
                         * Ethereum Address
                         * example:
                         * 0x71C7656EC7ab88b098defB751B7401B5f6d8976F
                         */
            ledgerContractAddress: string // ^0x([0-9A-Fa-f]){40}$
            /**
                         * Ethereum Address
                         * example:
                         * 0x71C7656EC7ab88b098defB751B7401B5f6d8976F
                         */
            ledgerSignerAddress: string // ^0x([0-9A-Fa-f]){40}$
            pooToPorDelay: number
            pooToPopDelay: number
            pooToSecretDelay: number
          }
          signatures: {
            /**
                         * CompactJWS
                         */
            providerSignature: string // ^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$
            /**
                         * CompactJWS
                         */
            consumerSignature: string // ^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$
          }
        }
      } | {
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
        parentResource?: string
        /**
                 * DID
                 * example:
                 * did:ethr:i3m:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                 */
        identity?: string // ^did:ethr:(\w+:)?0x([0-9a-fA-F]{40}([0-9a-fA-F]{26})?)$
        resource: string // ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$
      }>
      /**
             * Error
             */
      export interface Default {
        code: number // int32
        message: string
      }
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
      /**
             * Error
             */
      export interface Default {
        code: number // int32
        message: string
      }
    }
  }
  export namespace TransactionDeploy {
    /**
         * SignedTransaction
         * A list of resources
         */
    export interface RequestBody {
      transaction?: string // ^0x(?:[A-Fa-f0-9])+$
    }
    export namespace Responses {
      export interface $200 {
      }
      /**
             * Error
             */
      export interface Default {
        code: number // int32
        message: string
      }
    }
  }
}
