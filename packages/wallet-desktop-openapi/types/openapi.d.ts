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
                 * DID
                 * example:
                 * did:ethr:rinkeby:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                 */
        Did
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
         * did:ethr:rinkeby:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
         */
    export type Did = string
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
             * DID
             * example:
             * did:ethr:rinkeby:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      Did
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
      addresses?: string[]
    }
    /**
         * IdentityListInput
         * A list of DIDs
         */
    export type IdentityListInput = Array<{
      did: /**
             * DID
             * example:
             * did:ethr:rinkeby:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      Did
    }>
    /**
         * IdentitySelectOutput
         */
    export interface IdentitySelectOutput {
      did: /**
             * DID
             * example:
             * did:ethr:rinkeby:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      Did
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
    export type Resource = /* Resource */ /* VerifiableCredential */ VerifiableCredential
    export interface ResourceId {
      id: string
    }
    /**
         * ResourceListOutput
         * A list of resources
         */
    export type ResourceListOutput = ResourceId[]
    export type ResourceType = 'VerifiableCredential'
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
      type: 'VerifiableCredential'
      identity?: /**
             * DID
             * example:
             * did:ethr:rinkeby:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
      Did
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
                     * DID
                     * example:
                     * did:ethr:rinkeby:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                     */
          Did
        }
        /**
                 * example:
                 * 2021-06-10T19:07:28.000Z
                 */
        issuanceDate: string // date-time
        credentialSubject: {
          [name: string]: any
          id: /**
                     * DID
                     * example:
                     * did:ethr:rinkeby:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                     */
          Did
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
             * DID
             * example:
             * did:ethr:rinkeby:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
            WalletComponents.Schemas.Did
    }
    export interface PathParameters {
      did: Parameters.Did
    }
    export type RequestBody = /* Transaction */ WalletComponents.Schemas.Transaction
    export namespace Responses {
      export type $200 = /* Receipt */ WalletComponents.Schemas.Receipt
    }
  }
  export namespace IdentityInfo {
    export namespace Parameters {
      export type Did = /**
             * DID
             * example:
             * did:ethr:rinkeby:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
            WalletComponents.Schemas.Did
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
    }
  }
  export namespace IdentitySign {
    export namespace Parameters {
      export type Did = /**
             * DID
             * example:
             * did:ethr:rinkeby:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
            WalletComponents.Schemas.Did
    }
    export interface PathParameters {
      did: Parameters.Did
    }
    export type RequestBody = /* SignInput */ WalletComponents.Schemas.SignInput
    export namespace Responses {
      export type $200 = /* SignOutput */ WalletComponents.Schemas.SignOutput
    }
  }
  export namespace Providerinfo {
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
