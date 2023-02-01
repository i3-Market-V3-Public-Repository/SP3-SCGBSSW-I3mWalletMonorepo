/* eslint-disable @typescript-eslint/no-empty-interface */
export namespace OpenApiComponents {
    export namespace Schemas {
        /**
         * Error
         */
        export interface ApiError {
            name: string;
            description: string;
        }
        /**
         * AuthToken
         * A bearer token a client can use to access its vault
         *
         */
        export interface AuthToken {
            /**
             * A bearer token a client can use to access its vault
             *
             */
            token: string;
        }
        /**
         * AuthorizationRequest
         * A set of registered username and authkey in order to get the server's token. `authkey` is a secret securely derived from the user's password, so can be recovered if the user remembers the password. `authkey` will work as a standard password server side.
         *
         */
        export interface AuthorizationRequest {
            /**
             * is a unique identifier for this client (the end user should be able to memorize it)
             *
             * example:
             * username
             */
            username: string;
            /**
             * is a secret securely derived from the user's password with base64url no padding, so it can be recovered if the user remembers the password. Key length is between 256 and 512 bits. `authkey` will work as a standard password server side.
             *
             * example:
             * uvATmXpCml3YNqyQ-w3CtJfiCOkHIXo4uUAEj4oshGQ
             */
            authkey: string // ^[a-zA-Z0-9_-]{43,86}$
        }
        /**
         * Encrypted Storage
         * EncryptedStorage is the JSON obejct representing the storage of registered users in the cloud vault
         *
         */
        export interface EncryptedStorage {
            /**
             * A JWE containing the encrypted storage
             *
             */
            jwe: string // ^[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]*){4}$
            /**
             * A timestamp expressed in milliseconds elapsed since the epoch. The timestamp refers to the exact time the latest storage was registered in the cloud vault.
             * example:
             * 1674060143749
             */
            timestamp?: number;
        }
        /**
         * JWK Elliptic-Curve Public Key Object
         * A JWK Key Object representing a public key generated with Elliptic-Curve cryptography.
         *
         */
        export interface JwkEcPublicKey {
            /**
             * The alg member identifies the cryptographic algorithm family used with the key.
             *
             * example:
             * ES256
             */
            alg: "ES256" | "ES384" | "ES512";
            /**
             * OPTIONAL. The "use" (public key use) parameter identifies the intended use of the public key.  The "use" parameter is employed to indicate whether a public key is used for encrypting data or verifying the signature on data.
             *
             * Values defined by this specification are:
             * - "sig" (signature)
             * - "enc" (encryption)
             *
             * Other values MAY be used.  The "use" value is a case-sensitive string.  Use of the "use" member is OPTIONAL, unless the application requires its presence.
             *
             * example:
             * sig
             */
            use?: string;
            /**
             * The "kid" (key ID) parameter is used to match a specific key. This is used, for instance, to choose among a set of keys within a JWK Set during key rollover.  The structure of the "kid" value is unspecified.  When "kid" values are used within a JWK Set, different keys within the JWK Set SHOULD use distinct "kid" values.  (One example in which different keys might use the same "kid" value is if they have different "kty" (key type) values but are considered to be equivalent alternatives by the application using them.) The "kid" value is a case-sensitive string. When used with JWS or JWE, the "kid" value is used to match a JWS or JWE "kid" Header Parameter value.
             *
             */
            kid?: string;
            /**
             * The cryptographic curve used with the key. Values defined by this specification are P-256, P-384 and P-521. Additional "crv" values MAY be used, provided they are understood by implementations using that Elliptic Curve key. The "crv" value is case sensitive.
             *
             * example:
             * P-256
             */
            crv: "P-256" | "P-384" | "P-521";
            /**
             * The "x" coordinate for the elliptic curve point. It is represented as the base64url encoding of the big endian representation of the coordinate.
             *
             * example:
             * 2Rwrw2sbff-EnjbRi5sSJ09FRKhBPO7SsCxRwfBCpx4
             */
            x: string // ^[A-Za-z0-9_-]+$
            /**
             * The "y" coordinate for the elliptic curve point. It is represented as the base64url encoding of the big endian representation of the coordinate
             *
             * example:
             * r-qUFiNmBZqr00pTyUZPPLsBsmEW8pH7_vtBVOPVsi0
             */
            y: string // ^[A-Za-z0-9_-]+$
        }
        /**
         * RegistrationData
         * A compact JWE encrypted with this server's public key with the following payload:
         *
         * ```json
         * {
         *   did: string
         *   username: string
         *   authkey: string
         * }
         * ```
         *
         * - `did` is the did of the user. The required authorization forces the user to prove that is the owner of this `did`
         * - `username` is a unique username proposed by the client (it should be able to memorize it)
         * - `authkey` is a secret securely derived from the user's password, so can be recovered if the user remembers the password. `authkey` will work as a standard password server side.
         *
         */
        export type RegistrationData = string // ^[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]*){4}$
        /**
         * Registration Response
         * The registration response object.
         *
         */
        export interface RegistrationResponse {
            /**
             * whether the proposed username has been registered or not (because another one was previously registered)
             */
            status: "created" | "already registered";
            /**
             * - `status === 'created'`: the registered username
             * - `status === 'already registered'`: the username that was previously registered fot the same DID.
             *
             */
            username: string;
            /**
             * The endpoint where to authenticate with `username` and its corresponding `authkey` (which is derived from the user's password) in order to get a valid API token for the Cloud Vault.
             *
             */
            auth_endpoint: string;
        }
        /**
         * Timestamp
         * A timestamp expressed in milliseconds elapsed since the epoch. The timestamp refers to the exact time the latest storage was registered in the cloud vault.
         *
         */
        export interface Timestamp {
            /**
             * A timestamp expressed in milliseconds elapsed since the epoch. The timestamp refers to the exact time the latest storage was registered in the cloud vault.
             * example:
             * 1674060143749
             */
            timestamp: number;
        }
    }
}
export namespace OpenApiPaths {
    export namespace ApiV2Registration$Data {
        export namespace Get {
            export namespace Parameters {
                export type Data = /**
                 * RegistrationData
                 * A compact JWE encrypted with this server's public key with the following payload:
                 *
                 * ```json
                 * {
                 *   did: string
                 *   username: string
                 *   authkey: string
                 * }
                 * ```
                 *
                 * - `did` is the did of the user. The required authorization forces the user to prove that is the owner of this `did`
                 * - `username` is a unique username proposed by the client (it should be able to memorize it)
                 * - `authkey` is a secret securely derived from the user's password, so can be recovered if the user remembers the password. `authkey` will work as a standard password server side.
                 *
                 */
                OpenApiComponents.Schemas.RegistrationData /* ^[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]*){4}$ */;
            }
            export interface PathParameters {
                data: Parameters.Data;
            }
            export namespace Responses {
                export type $201 = /**
                 * Registration Response
                 * The registration response object.
                 *
                 */
                OpenApiComponents.Schemas.RegistrationResponse;
                export type Default = /* Error */ OpenApiComponents.Schemas.ApiError;
            }
        }
    }
    export namespace ApiV2RegistrationPublicJwk {
        export namespace Get {
            export namespace Responses {
                export interface $200 {
                    jwk: /**
                     * JWK Elliptic-Curve Public Key Object
                     * A JWK Key Object representing a public key generated with Elliptic-Curve cryptography.
                     *
                     */
                    OpenApiComponents.Schemas.JwkEcPublicKey;
                }
                export type Default = /* Error */ OpenApiComponents.Schemas.ApiError;
            }
        }
    }
    export namespace ApiV2Vault {
        export namespace Delete {
            export namespace Responses {
                export interface $204 {
                }
                export type Default = /* Error */ OpenApiComponents.Schemas.ApiError;
            }
        }
        export namespace Get {
            export namespace Responses {
                /**
                 * Encrypted Storage
                 * EncryptedStorage is the JSON obejct representing the storage of registered users in the cloud vault
                 *
                 */
                export interface $200 {
                    /**
                     * A JWE containing the encrypted storage
                     *
                     */
                    jwe: string // ^[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]*){4}$
                    /**
                     * A timestamp expressed in milliseconds elapsed since the epoch. The timestamp refers to the exact time the latest storage was registered in the cloud vault.
                     * example:
                     * 1674060143749
                     */
                    timestamp: number;
                }
                export type Default = /* Error */ OpenApiComponents.Schemas.ApiError;
            }
        }
        export namespace Post {
            export type RequestBody = /**
             * Encrypted Storage
             * EncryptedStorage is the JSON obejct representing the storage of registered users in the cloud vault
             *
             */
            OpenApiComponents.Schemas.EncryptedStorage;
            export namespace Responses {
                export type $201 = /**
                 * Timestamp
                 * A timestamp expressed in milliseconds elapsed since the epoch. The timestamp refers to the exact time the latest storage was registered in the cloud vault.
                 *
                 */
                OpenApiComponents.Schemas.Timestamp;
                export type Default = /* Error */ OpenApiComponents.Schemas.ApiError;
            }
        }
    }
    export namespace ApiV2VaultAuth {
        export namespace Post {
            export type RequestBody = /**
             * AuthorizationRequest
             * A set of registered username and authkey in order to get the server's token. `authkey` is a secret securely derived from the user's password, so can be recovered if the user remembers the password. `authkey` will work as a standard password server side.
             *
             */
            OpenApiComponents.Schemas.AuthorizationRequest;
            export namespace Responses {
                export type $200 = /**
                 * AuthToken
                 * A bearer token a client can use to access its vault
                 *
                 */
                OpenApiComponents.Schemas.AuthToken;
                export type Default = /* Error */ OpenApiComponents.Schemas.ApiError;
            }
        }
    }
    export namespace ApiV2VaultEvents {
        export namespace Get {
            export namespace Responses {
                export interface $200 {
                }
            }
        }
    }
    export namespace ApiV2VaultTimestamp {
        export namespace Get {
            export namespace Responses {
                export type $200 = /**
                 * Timestamp
                 * A timestamp expressed in milliseconds elapsed since the epoch. The timestamp refers to the exact time the latest storage was registered in the cloud vault.
                 *
                 */
                OpenApiComponents.Schemas.Timestamp;
                export type Default = /* Error */ OpenApiComponents.Schemas.ApiError;
            }
        }
    }
}
