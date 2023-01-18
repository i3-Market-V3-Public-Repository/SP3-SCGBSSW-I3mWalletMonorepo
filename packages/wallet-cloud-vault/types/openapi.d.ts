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
         * JWK Elliptic-Curve Publick Key Object
         * A JWK Key Object representing a private key generated with Elliptic-Curve cryptography.
         *
         */
        export interface JwkEcPrivateKey {
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
             * The "x" coordinate for the elliptic curve point. It is represented as the base64url encoding of the coordinate's big endian representation.
             *
             * example:
             * 2Rwrw2sbff-EnjbRi5sSJ09FRKhBPO7SsCxRwfBCpx4
             */
            x: string // ^[A-Za-z0-9_-]+$
            /**
             * The "y" coordinate for the elliptic curve point. It is represented as the base64url encoding of the coordinate's big endian representation.
             *
             * example:
             * r-qUFiNmBZqr00pTyUZPPLsBsmEW8pH7_vtBVOPVsi0
             */
            y: string // ^[A-Za-z0-9_-]+$
            /**
             * The private key. It is represented as the base64url encoding of the coordinate's big endian representation.
             *
             * example:
             * bbU2QoQC3eGKvBUjhAkfx_ZzsCzhkPTICItA0wgX1uM
             */
            d: string // ^[A-Za-z0-9_-]+$
        }
        /**
         * JWK Elliptic-Curve Publick Key Object
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
             * The "x" coordinate for the elliptic curve point. It is represented as the base64url encoding of the coordinate's big endian representation.
             *
             * example:
             * 2Rwrw2sbff-EnjbRi5sSJ09FRKhBPO7SsCxRwfBCpx4
             */
            x: string // ^[A-Za-z0-9_-]+$
            /**
             * The "y" coordinate for the elliptic curve point. It is represented as the base64url encoding of the coordinate's big endian representation.
             *
             * example:
             * r-qUFiNmBZqr00pTyUZPPLsBsmEW8pH7_vtBVOPVsi0
             */
            y: string // ^[A-Za-z0-9_-]+$
        }
    }
}
export namespace OpenApiPaths {
    export namespace ApiV2PublicJwk {
        export namespace Get {
            export namespace Responses {
                export type $200 = /**
                 * JWK Elliptic-Curve Publick Key Object
                 * A JWK Key Object representing a public key generated with Elliptic-Curve cryptography.
                 *
                 */
                OpenApiComponents.Schemas.JwkEcPublicKey;
                export type Default = /* Error */ OpenApiComponents.Schemas.ApiError;
            }
        }
    }
}
