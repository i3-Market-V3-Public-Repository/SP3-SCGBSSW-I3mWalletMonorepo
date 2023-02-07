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
         * Cloud-Vault-Server Well-Known Configuration
         */
        export interface CvsConfiguration {
            name: string;
            description?: string;
            registration_configuration: /* Registration Endpoints */ RegistrationConfiguration;
            vault_configuration: {
                [name: string]: /* Vault Well-Known Configuration */ VaultConfiguration;
                v2: /* Vault Well-Known Configuration */ VaultConfiguration;
            };
        }
        /**
         * Encrypted Storage
         * EncryptedStorage is the JSON obejct representing the storage of registered users in the cloud vault
         *
         */
        export interface EncryptedStorage {
            /**
             * The encrypted storage in base64url encoding
             *
             */
            ciphertext: string // ^[a-zA-Z0-9_-]+$
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
             * example:
             * EC
             */
            kty: "EC";
            /**
             * The alg member identifies the cryptographic algorithm family used with the key.
             *
             * example:
             * ES256
             */
            alg: "ES256" | "ES384" | "ES512";
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
        export interface KeyDerivationOptions {
            alg: "scrypt";
            /**
             * Desired key length in bytes
             */
            derived_key_length: number;
            /**
             * example:
             * password
             */
            input: "password" | "master-key";
            /**
             * Describes the salt pattern to use when deriving the key from a password. It is a UTF-8 string, where variables to replace wrapped in curly braces.
             *
             * The salt is a concatenation of key_name, server_id and username.
             *
             * The length is not important since the provided salt will be hashed before being used (see saltHashingAlgorithm)
             *
             * example:
             * master9u8tHv8_s-QsG8CxuAefhg{username}
             */
            salt_pattern: string;
            /**
             * Since salts are length contrained, and saltPattern creates salts with an arbitrary length, the input salt is hashed with the provided hash algorithm.
             *
             * example:
             * sha3-512
             */
            salt_hashing_algorithm: "sha3-256" | "sha3-384" | "sha3-512";
            alg_options: ScryptOptions;
        }
        /**
         * Registration Endpoints
         */
        export interface RegistrationConfiguration {
            /**
             * example:
             * /api/v2/registration/public-jwk
             */
            public_jwk_endpoint: string;
            /**
             * Endpoint for registering a new client. The endpoint requires authentication with valid i3-MARKET credentials.
             *
             * {data} refers to a compact JWE encrypted with this server's public key with the following payload:
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
             * example:
             * /api/v2/registration/{data}
             */
            registration_endpoint: string;
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
        }
        export interface ScryptOptions {
            /**
             * CPU/memory cost parameter – Must be a power of 2 (e.g. 1024)
             * example:
             * 2097152
             */
            N: number;
            /**
             * blocksize parameter, which fine-tunes sequential memory read size and performance. (8 is commonly used)
             */
            r: number;
            /**
             * Parallelization parameter. (1 .. 232-1 * hLen/MFlen)
             */
            p: number;
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
        /**
         * Vault Well-Known Configuration
         */
        export interface VaultConfiguration {
            /**
             * a unique id for this server
             */
            id: string;
            /**
             * the version of the API this configuration applies to
             * example:
             * v2
             */
            version: string;
            /**
             * the upper limit for the length in bytes of the vault storage
             */
            vault_size: number;
            /**
             * the vault endpoint where to GET, POST or DELETE the storage
             * example:
             * /api/v2/vault
             */
            vault_endpoint: string;
            /**
             * endpoint where the server where to subscribe for storage-update Server-Sent Events (SSE)
             * example:
             * /api/v2/vault/events
             */
            events_endpoint: string;
            /**
             * where to get the timestamp (in milliseconds elapsed since the epoch) of the latest uploaded storage
             * example:
             * /api/v2/vault/timsestamp
             */
            timestamp_endpoint: string;
            /**
             * the path on this server where to get a valid bearer token for operating with the vault
             * example:
             * /api/v2/vault/token
             */
            token_endpoint: string;
            /**
             * example:
             * [
             *   "client_secret_post"
             * ]
             */
            token_endpoint_auth_methods_supported: ("client_secret_post" | "client_secret_basic" | "client_secret_jwt" | "private_key_jwt")[];
            key_derivation: {
                master: KeyDerivationOptions;
                enc: {
                    alg: "scrypt";
                    /**
                     * Desired key length in bytes
                     */
                    derived_key_length: number;
                    /**
                     * example:
                     * password
                     */
                    input: "password" | "master-key";
                    /**
                     * Describes the salt pattern to use when deriving the key from a password. It is a UTF-8 string, where variables to replace wrapped in curly braces.
                     *
                     * The salt is a concatenation of key_name, server_id and username.
                     *
                     * The length is not important since the provided salt will be hashed before being used (see saltHashingAlgorithm)
                     *
                     * example:
                     * master9u8tHv8_s-QsG8CxuAefhg{username}
                     */
                    salt_pattern: string;
                    /**
                     * Since salts are length contrained, and saltPattern creates salts with an arbitrary length, the input salt is hashed with the provided hash algorithm.
                     *
                     * example:
                     * sha3-512
                     */
                    salt_hashing_algorithm: "sha3-256" | "sha3-384" | "sha3-512";
                    alg_options: ScryptOptions;
                    /**
                     * example:
                     * aes-256-gcm
                     */
                    enc_algorithm: "aes-192-gcm" | "aes-256-gcm";
                };
                auth: KeyDerivationOptions;
            };
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
                     * The encrypted storage in base64url encoding
                     *
                     */
                    ciphertext: string // ^[a-zA-Z0-9_-]+$
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
    export namespace ApiV2VaultToken {
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
    export namespace WellKnownCvsConfiguration {
        export namespace Get {
            export namespace Responses {
                export type $200 = /* Cloud-Vault-Server Well-Known Configuration */ OpenApiComponents.Schemas.CvsConfiguration;
                export type Default = /* Error */ OpenApiComponents.Schemas.ApiError;
            }
        }
    }
}
