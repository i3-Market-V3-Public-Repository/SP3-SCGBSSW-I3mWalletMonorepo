/* eslint-disable @typescript-eslint/no-empty-interface */
export namespace WalletComponents {
    export namespace Schemas {
        /**
         * Error
         */
        export interface ApiError {
            code: number // int32
            message: string;
        }
        /**
         * DID
         * example:
         * did:ethr:rinkeby:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
         */
        export type Did = string;
        /**
         * IdentityCreateInput
         * Besides the here defined options, provider specific properties should be added here if necessary, e.g. "path" for BIP21 wallets, or the key algorithm (if the wallet supports multiple algorithm).
         *
         */
        export interface IdentityCreateInput {
            [name: string]: any;
            alias?: string;
        }
        /**
         * IdentityCreateOutput
         * It returns the account id and type
         *
         */
        export interface IdentityCreateOutput {
            [name: string]: any;
            did: /**
             * DID
             * example:
             * did:ethr:rinkeby:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
            Did;
        }
        /**
         * IdentityListInput
         * A list of DIDs
         */
        export type IdentityListInput = {
            did: /**
             * DID
             * example:
             * did:ethr:rinkeby:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
            Did;
        }[];
        /**
         * IdentitySelectOutput
         */
        export interface IdentitySelectOutput {
            did: /**
             * DID
             * example:
             * did:ethr:rinkeby:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
            Did;
        }
        /**
         * Resource
         */
        export type Resource = /* Resource */ /* VerifiableCredential */ VerifiableCredential;
        export interface ResourceId {
            id: string;
        }
        /**
         * ResourceListOutput
         * A list of resources
         */
        export type ResourceListOutput = ResourceId[];
        export type ResourceType = "VerifiableCredential";
        /**
         * SignInput
         */
        export type SignInput = /* SignInput */ /* SignTransaction */ SignTransaction;
        /**
         * SignOutput
         */
        export interface SignOutput {
            signature: string;
        }
        /**
         * SignTransaction
         */
        export interface SignTransaction {
            type?: "Transaction";
            data?: /* Transaction */ Transaction;
        }
        /**
         * SignTypes
         */
        export type SignTypes = "Transaction";
        /**
         * Transaction
         */
        export interface Transaction {
            from?: string;
        }
        /**
         * VerifiableCredential
         */
        export interface VerifiableCredential {
            type: "VerifiableCredential";
            identity?: /**
             * DID
             * example:
             * did:ethr:rinkeby:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
            Did;
            resource: {
                [name: string]: any;
                /**
                 * example:
                 * [
                 *   "https://www.w3.org/2018/credentials/v1"
                 * ]
                 */
                "@context": string[];
                /**
                 * example:
                 * http://example.edu/credentials/1872
                 */
                id?: string;
                /**
                 * example:
                 * [
                 *   "VerifiableCredential"
                 * ]
                 */
                type: string[];
                issuer: {
                    [name: string]: any;
                    id: /**
                     * DID
                     * example:
                     * did:ethr:rinkeby:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                     */
                    Did;
                };
                /**
                 * example:
                 * 2021-06-10T19:07:28.000Z
                 */
                issuanceDate: string // date-time
                credentialSubject: {
                    [name: string]: any;
                    id: /**
                     * DID
                     * example:
                     * did:ethr:rinkeby:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
                     */
                    Did;
                };
                proof: {
                    [name: string]: any;
                    type: "JwtProof2020";
                };
            };
        }
    }
}
export namespace WalletPaths {
    export namespace IdentityCreate {
        export type RequestBody = /**
         * IdentityCreateInput
         * Besides the here defined options, provider specific properties should be added here if necessary, e.g. "path" for BIP21 wallets, or the key algorithm (if the wallet supports multiple algorithm).
         *
         */
        WalletComponents.Schemas.IdentityCreateInput;
        export namespace Responses {
            export type $201 = /**
             * IdentityCreateOutput
             * It returns the account id and type
             *
             */
            WalletComponents.Schemas.IdentityCreateOutput;
            export type Default = /* Error */ WalletComponents.Schemas.ApiError;
        }
    }
    export namespace IdentityList {
        export namespace Parameters {
            /**
             * An alias for the identity
             */
            export type Alias = string;
        }
        export interface QueryParameters {
            alias?: /* An alias for the identity */ Parameters.Alias;
        }
        export namespace Responses {
            export type $200 = /**
             * IdentityListInput
             * A list of DIDs
             */
            WalletComponents.Schemas.IdentityListInput;
            export type Default = /* Error */ WalletComponents.Schemas.ApiError;
        }
    }
    export namespace IdentitySelect {
        export namespace Parameters {
            /**
             * Message to show to the user with the reason to pick an identity
             */
            export type Reason = string;
        }
        export interface QueryParameters {
            reason?: /* Message to show to the user with the reason to pick an identity */ Parameters.Reason;
        }
        export namespace Responses {
            export type $200 = /* IdentitySelectOutput */ WalletComponents.Schemas.IdentitySelectOutput;
        }
    }
    export namespace IdentitySign {
        export namespace Parameters {
            export type Did = /**
             * DID
             * example:
             * did:ethr:rinkeby:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
             */
            WalletComponents.Schemas.Did;
        }
        export interface PathParameters {
            did: Parameters.Did;
        }
        export type RequestBody = /* SignInput */ WalletComponents.Schemas.SignInput;
        export namespace Responses {
            export type $200 = /* SignOutput */ WalletComponents.Schemas.SignOutput;
        }
    }
    export namespace ResourceCreate {
        export type RequestBody = /* Resource */ WalletComponents.Schemas.Resource;
        export namespace Responses {
            export type $201 = WalletComponents.Schemas.ResourceId;
            export type Default = /* Error */ WalletComponents.Schemas.ApiError;
        }
    }
    export namespace ResourceList {
        export namespace Responses {
            export type $200 = /**
             * ResourceListOutput
             * A list of resources
             */
            WalletComponents.Schemas.ResourceListOutput;
            export type Default = /* Error */ WalletComponents.Schemas.ApiError;
        }
    }
    export namespace SelectiveDisclosure {
        export namespace Parameters {
            export type Jwt = string // ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$
        }
        export interface PathParameters {
            jwt: Parameters.Jwt /* ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ */;
        }
        export namespace Responses {
            export interface $200 {
                jwt?: string;
            }
            export type Default = /* Error */ WalletComponents.Schemas.ApiError;
        }
    }
}
