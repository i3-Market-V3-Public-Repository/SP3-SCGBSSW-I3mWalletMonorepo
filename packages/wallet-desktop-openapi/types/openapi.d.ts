/* eslint-disable @typescript-eslint/no-empty-interface */
export namespace WalletComponents {
  export namespace Parameters {
    export namespace CallbackUriQuery {
      export type Cb = string // uri
    }
  }
  export namespace Schemas {
    /**
         * Account
         */
    export interface Account {
      [name: string]: any
      id: /**
             * AccountId
             * example:
             * m/44'/60'/0'/0/2
             */
      AccountId
      name?: string
      description?: string
      type?: /* AccountType */ AccountType
      key?: /**
             * JWK
             * example:
             * {
             *   "kty": "EC",
             *   "crv": "P-256",
             *   "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
             *   "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
             *   "kid": "12"
             * }
             */
      JWK
    }
    /**
         * AccountCreateInput
         * Besides the here defined options, provider specific properties should be added here if necessary, e.g. "path" for BIP21 wallets, or the key algorithm (if the wallet supports multiple algorithm).
         *
         */
    export interface AccountCreateInput {
      [name: string]: any
      type?: any
      name?: string
      comment?: string
    }
    /**
         * AccountCreateOutput
         * It returns the account id and type
         *
         */
    export interface AccountCreateOutput {
      [name: string]: any
      type: /* AccountType */ AccountType
      id: string
    }
    /**
         * AccountDecryptInput
         * An object containing:
         * - `accountId`: [OPTIONAL] if accountId is set, it will be used; otherwise, the end user will have to interactively select one account.
         * - `ciphertext`: an object containing base64url-encoded versions of the ciphertext, and the iv used to encrypt it (if used).
         *
         */
    export interface AccountDecryptInput {
      accountId?: /**
             * AccountId
             * example:
             * m/44'/60'/0'/0/2
             */
      AccountId
      ciphertext: /**
             * JWEFlattenedJSON
             * The flattened JWE JSON Serialization syntax is based upon the general syntax, but flattens it, optimizing it for the single-recipient case. It flattens it by removing the "recipients" member and instead placing those members defined for use in the "recipients" array (the "header" and "encrypted_key" members) in the top-level JSON object (at the same level as the "ciphertext" member).
             *
             * The "recipients" member MUST NOT be present when using this syntax. Other than this syntax difference, JWE JSON Serialization objects using the flattened syntax are processed identically to those using the general syntax.
             *
             * In summary, the syntax of a JWE using the flattened JWE JSON
             *
             * Serialization is as follows:
             *   {
             *     "protected":"<integrity-protected header contents>",
             *     "unprotected":<non-integrity-protected header contents>,
             *     "header":<more non-integrity-protected header contents>,
             *     "encrypted_key":"<encrypted key contents>",
             *     "aad":"<additional authenticated data contents>",
             *     "iv":"<initialization vector contents>",
             *     "ciphertext":"<ciphertext contents>",
             *     "tag":"<authentication tag contents>"
             *   }
             *
             * Note that when using the flattened syntax, just as when using the
             * general syntax, any unprotected Header Parameter values can reside in
             * either the "unprotected" member or the "header" member, or in both.
             *
             * example:
             * {
             *   "protected": "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
             *   "unprotected": {
             *     "jku": "https://server.example.com/keys.jwks"
             *   },
             *   "header": {
             *     "alg": "A128KW",
             *     "kid": "7"
             *   },
             *   "encrypted_key": "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ\"",
             *   "iv": "AxY8DCtDaGlsbGljb3RoZQ",
             *   "ciphertext": "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY\"",
             *   "tag": "Mz-VPPyU4RlcuYv1IwIvzw"
             * }
             */
      JWEFlattenedJSON
    }
    /**
         * AccountDecryptOutput
         * The decrypted message Base64Url
         */
    export type AccountDecryptOutput = string // ^[A-Za-z0-9_-]+$
    /**
         * AccountEncryptInput
         * An object containing:
         * - `accountId`: [OPTIONAL] if accountId is set, it will be used; otherwise, the end user will have to interactively select one account.
         * - `input`: base64url-encoded versions of the plaintext to encrypt, and an optional iv (random one will be chosen if not provided).
         *
         */
    export interface AccountEncryptInput {
      accountId?: /**
             * AccountId
             * example:
             * m/44'/60'/0'/0/2
             */
      AccountId
      encryptInput: {
        /**
                 * the plaintext to be encrypted in Base64Url
                 */
        plaintext: string // ^[A-Za-z0-9_-]+$
        /**
                 * OPTIONAL. Base64Url-encoded iv to use for encryption (if required)
                 */
        iv?: string // ^[A-Za-z0-9_-]+$
      }
    }
    /**
         * AccountEncryptOutput
         * The flattened JWE JSON Serialization syntax is based upon the general syntax, but flattens it, optimizing it for the single-recipient case. It flattens it by removing the "recipients" member and instead placing those members defined for use in the "recipients" array (the "header" and "encrypted_key" members) in the top-level JSON object (at the same level as the "ciphertext" member).
         *
         * The "recipients" member MUST NOT be present when using this syntax. Other than this syntax difference, JWE JSON Serialization objects using the flattened syntax are processed identically to those using the general syntax.
         *
         * In summary, the syntax of a JWE using the flattened JWE JSON
         *
         * Serialization is as follows:
         *   {
         *     "protected":"<integrity-protected header contents>",
         *     "unprotected":<non-integrity-protected header contents>,
         *     "header":<more non-integrity-protected header contents>,
         *     "encrypted_key":"<encrypted key contents>",
         *     "aad":"<additional authenticated data contents>",
         *     "iv":"<initialization vector contents>",
         *     "ciphertext":"<ciphertext contents>",
         *     "tag":"<authentication tag contents>"
         *   }
         *
         * Note that when using the flattened syntax, just as when using the
         * general syntax, any unprotected Header Parameter values can reside in
         * either the "unprotected" member or the "header" member, or in both.
         *
         * example:
         * {
         *   "protected": "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
         *   "unprotected": {
         *     "jku": "https://server.example.com/keys.jwks"
         *   },
         *   "header": {
         *     "alg": "A128KW",
         *     "kid": "7"
         *   },
         *   "encrypted_key": "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ\"",
         *   "iv": "AxY8DCtDaGlsbGljb3RoZQ",
         *   "ciphertext": "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY\"",
         *   "tag": "Mz-VPPyU4RlcuYv1IwIvzw"
         * }
         */
    export interface AccountEncryptOutput {
      /**
             * BASE64URL(UTF8(JWE Protected Header))
             *
             * The JWE Protected Header declares:
             *   - `alg`: algorithm to encrypt a fresh and randomly generated Content Encryption Key (CEK) `encrypted_key`
             *   - `enc`: the content encryption algorithm. It should be a symmetric Authenticated Encryption with Associated Data (AEAD) algorithm. Contents will we encrypted using `enc` algorithm with the `encrypted_key`
             *   - `kid`: an identifier of the key that shold be used to decrypt the `encrypted_key`
             *
             * The "protected" member MUST be present and contain the value BASE64URL(UTF8(JWE Protected Header)) when the JWE Protected Header value is non-empty; otherwise, it MUST be absent. These Header Parameter values are integrity protected.
             *
             * An example JWE Protected header is:
             * `{"alg":"ES256","enc":"A256GCM","kid":"did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#key-1"}`
             *
             * example:
             * eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiRVMyNTYiLCJraWQiOiJkaWQ6ZXRocjoweGI5YzU3MTQwODk0NzhhMzI3ZjA5MTk3OTg3ZjE2ZjllNWQ5MzZlOGEja2V5LTEifQ
             */
      protected?: string // ^[A-Za-z0-9_-]+$
      /**
             * JWE Unprotected Header
             *
             * Non-integrity-protected header contents
             *
             * The "unprotected" member MUST be present and contain the value JWE Shared Unprotected Header when the JWE Shared Unprotected Header value is non-empty; otherwise, it MUST be absent. This value is represented as an unencoded JSON object, rather than as a string. These Header Parameter values are not integrity protected.
             *
             */
      unprotected?: {
        [name: string]: any
      }
      /**
             * More non-integrity-protected header contents
             *
             * The "header" member MUST be present and contain the value JWE Per-Recipient Unprotected Header when the JWE Per-Recipient Unprotected Header value is non-empty; otherwise, it MUST be absent. This value is represented as an unencoded JSON object, rather than as a string. These Header Parameter values are not integrity protected.
             *
             */
      header?: {
        [name: string]: any
        alg?: /**
                 * The "alg" (algorithm) parameter identifies the algorithm intended for use with the key. In JWE is a header parameter that identifies the cryptographic algorithm used to encrypt or determine the value of the CEK.
                 *
                 * The values used should either be registered in the IANA "JSON Web Signature and Encryption Algorithms" registry established by [JWA]((http://www.rfc-editor.org/info/rfc7518)) or be a value that contains a Collision-Resistant Name. The "alg" value is a case-sensitive ASCII string.
                 *
                 * example:
                 * ES256
                 */
        Alg
        enc?: /**
                 * The "enc" (encryption algorithm) Header Parameter identifies the content encryption algorithm used to perform authenticated encryption on the plaintext to produce the ciphertext and the Authentication Tag. This algorithm MUST be an AEAD algorithm with a specified key length. The encrypted content is not usable if the "enc" value does not represent a supported algorithm. "enc" values should either be registered in the IANA "JSON Web Signature and Encryption Algorithms" registry established by [JWA] or be a value that contains a Collision-Resistant Name.  The "enc" value is a case-sensitive ASCII string containing a StringOrURI value. This Header Parameter MUST be present and MUST be understood and processed by implementations.
                 *
                 * A list of defined "enc" values for this use can be found in the IANA "JSON Web Signature and Encryption Algorithms" registry established by [JWA]; the initial contents of this registry are the values defined in Section 5.1 of [JWA].
                 *
                 * example:
                 * A256GCM
                 */
        Enc
        zip?: /**
                 * The "zip" (compression algorithm) applied to the plaintext before encryption, if any. The "zip" value defined by RFC7516 specification is "DEF" (Compression with the DEFLATE [RFC1951] algorithm) although other values MAY be used. Compression algorithm values can be registered in the IANA "JSON Web Encryption Compression Algorithms" registry established by [JWA]. The "zip" value is a case-sensitive string.  If no "zip" parameter is present, no compression is applied to the plaintext before encryption. When used, this Header Parameter MUST be integrity protected; therefore, it MUST occur only within the JWE Protected Header. Use of this Header Parameter is OPTIONAL. This Header Parameter MUST be understood and processed by implementations.
                 *
                 */
        Zip
        jku?: /**
                 * The "jku" (JWK Set URL) is a URI [RFC3986] that refers to a resource for a set of JSON-encoded public keys, one of which corresponds to the key used to digitally sign the JWS. The keys MUST be encoded as a JWK Set [JWK]. The protocol used to acquire the resource MUST provide integrity protection; an HTTP GET request to retrieve the JWK Set MUST use Transport Layer Security (TLS) [RFC2818] [RFC5246]; and the identity of the server MUST be validated, as per Section 6 of RFC 6125 [RFC6125]. Also, see Section 8 on TLS requirements.
                 *
                 */
        Jku /* uri */
        jwk?: /**
                 * The "jwk" (JSON Web Key) when in a JWS header is the public key that corresponds to the key used to digitally sign the JWS. This key is represented as a JSON Web Key [JWK]
                 *
                 */
        Jwk /* ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ */
        kid?: /**
                 * The "kid" (key ID) parameter is used to match a specific key. This is used, for instance, to choose among a set of keys within a JWK Set during key rollover.  The structure of the "kid" value is unspecified.  When "kid" values are used within a JWK Set, different keys within the JWK Set SHOULD use distinct "kid" values.  (One example in which different keys might use the same "kid" value is if they have different "kty" (key type) values but are considered to be equivalent alternatives by the application using them.) The "kid" value is a case-sensitive string. When used with JWS or JWE, the "kid" value is used to match a JWS or JWE "kid" Header Parameter value.
                 *
                 * example:
                 * ES256
                 */
        Kid
        x5u?: /**
                 * The "x5u" (X.509 URL) parameter is a URI [RFC3986] that refers to a resource for an X.509 public key certificate or certificate chain [RFC5280]
                 *
                 */
        X5u
        x5c?: /**
                 * The "x5c" (X.509 certificate chain) parameter contains a chain of one or more PKIX certificates [RFC5280].
                 *
                 */
        X5c
        x5t?: /**
                 * The "x5t" (X.509 certificate SHA-1 thumbprint) parameter is a base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate [RFC5280].  Note that certificate thumbprints are also sometimes known as certificate fingerprints. The key in the certificate MUST match the public key represented by other members of the JWK.
                 *
                 */
        X5t
        'x5t#S256'?: /**
                 * x5t#S256
                 * The "x5t#S256" (X.509 certificate SHA-256 thumbprint) parameter is a base64url-encoded SHA-256 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate [RFC5280].  Note that certificate thumbprints are also sometimes known as certificate fingerprints. The key in the certificate MUST match the public key represented by other members of the JWK.
                 *
                 */
        X5tS256
        typ?: /**
                 * The "typ" (type) Header Parameter is used by JWS applications to the media type [IANA.MediaTypes] of this complete JWS. This is intended for use by the application when more than one kind of object could be present in an application data structure that can contain a JWS; the application can use this value to disambiguate among the different kinds of objects that might be present. It will typically not be used by applications when the kind of object is already known. This parameter is ignored by JWS implementations; any processing of this parameter is performed by the JWS application.
                 *
                 * Per RFC 2045 [RFC2045], all media type values, subtype values, and parameter names are case insensitive.  However, parameter values are
                 * case sensitive unless otherwise specified for the specific parameter. To keep messages compact in common situations, it is RECOMMENDED that
                 * producers omit an "application/" prefix of a media type value in a "typ" Header Parameter when no other '/' appears in the media type value. A recipient using the media type value MUST treat it as if "application/" were prepended to any "typ" value not containing a '/'.  For instance, a "typ" value of "example" SHOULD be used to represent the "application/example" media type, whereas the media type "application/example;part="1/2"" cannot be shortened to
                 * "example;part="1/2"".
                 *
                 * The "typ" value "JOSE" can be used by applications to indicate that this object is a JWS or JWE using the JWS Compact Serialization or the JWE Compact Serialization. The "typ" value "JOSE+JSON" can be used by applications to indicate that this object is a JWS or JWE using the JWS JSON Serialization or the JWE JSON Serialization. Other type values can also be used by applications.
                 *
                 * example:
                 * JOSE+JSON
                 */
        Typ
        cty?: /**
                 * The "cty" (content type) Header Parameter is used by JWS applications to the media type [IANA.MediaTypes] of the secured content (the payload).  This is intended for use by the application when more than one kind of object could be present in the JWS Payload; the application can use this value to disambiguate among the different kinds of objects that might be present. It will typically not be used by applications when the kind of object is already known. This parameter is ignored by JWS implementations; any processing of this parameter is performed by the JWS application.
                 *
                 * Per RFC 2045 [RFC2045], all media type values, subtype values, and parameter names are case insensitive. However, parameter values are case sensitive unless otherwise specified for the specific parameter.
                 *
                 * To keep messages compact in common situations, it is RECOMMENDED that producers omit an "application/" prefix of a media type value in a "cty" Header Parameter when no other '/' appears in the media type value.  A recipient using the media type value MUST treat it as if "application/" were prepended to any "cty" value not containing a '/'.  For instance, a "cty" value of "example" SHOULD be used to represent the "application/example" media type, whereas the media type "application/example;part="1/2"" cannot be shortened to "example;part="1/2"".
                 *
                 */
        Cty
        crit?: /**
                 * The "crit" (critical) Header Parameter indicates that extensions to this specification and/or [JWA] are being used that MUST be understood and processed.
                 *
                 * Its value is an array listing the Header Parameter names present in the JOSE Header that use those extensions. If any of the listed extension Header Parameters are not understood and supported by the recipient, then the JWS is invalid. Producers MUST NOT include Header Parameter names defined by this specification or [JWA] for use with JWS, duplicate names, or names that do not occur as Header Parameter names within the JOSE Header in the "crit" list.  Producers MUST NOT use the empty list "[]" as the "crit" value. Recipients MAY consider the JWS to be invalid if the critical list contains any Header Parameter names defined by this specification or [JWA] for use with JWS or if any other constraints on its use are violated.  When used, this Header Parameter MUST be integrity protected; therefore, it MUST occur only within the JWS Protected Header.
                 *
                 * This Header Parameter MUST be understood and processed by implementations.
                 *
                 * An example use, along with a hypothetical "exp" (expiration time) field is:
                 *   {"alg":"ES256",
                 *     "crit":["exp"],
                 *     "exp":1363284000
                 *   }
                 *
                 * example:
                 * [
                 *   "exp"
                 * ]
                 */
        Crit
      }
      /**
             * BASE64URL(JWE Encrypted Key)
             * It should be decrypted with the key identified in the `kid` protected header parameter. Once decrypted, it can be used to decrypt the `ciphertext`
             *
             */
      encrypted_key?: string // ^[A-Za-z0-9_-]+$
      /**
             * OPTIONAL. BASE64URL(JWE additional Authenticated Data contents). A JWE AAD value can be included to supply a base64url-encoded value to be integrity protected but not encrypted.
             *
             */
      aad?: string // ^[A-Za-z0-9_-]+$
      /**
             * OPTIONAL. BASE64URL(JWE Initialization Vector)
             * Initialization Vector value used when encrypting the plaintext
             *
             */
      iv?: string // ^[A-Za-z0-9_-]+$
      /**
             * BASE64URL(JWE Ciphertext)
             */
      ciphertext?: string // ^[A-Za-z0-9_-]+$
      /**
             * OPTIONAL. BASE64URL(JWE Authentication Tag)
             * An output of an AEAD operation that ensures the integrity of the ciphertext and the Additional Authenticated Data.  Note that some algorithms may not use an Authentication Tag, in which case this value is the empty octet sequence.
             *
             */
      tag?: string // ^[A-Za-z0-9_-]+$
    }
    /**
         * AccountId
         * example:
         * m/44'/60'/0'/0/2
         */
    export type AccountId = string
    /**
         * AccountListInput
         */
    export interface AccountListInput {
      account_ids?: string[]
      /**
             * a comma-separated list of props to retrieve from the account besides the account id. Props differ depending on the type of account ('identity' or 'secret')
             */
      props?: string[]
    }
    /**
         * AccountListOutput
         */
    export type AccountListOutput = /* Account */ Account[]
    /**
         * AccountSignInput
         * An object containing:
         * - `accountId`: [OPTIONAL] if accountId is set, it will be used; otherwise, the end user will have to interactively select one account.
         * - `messageToSign`: It can be either an plain object or a string (preferably a BASE64URL). Examples:
         *   `eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDpldGhyOjB4YjljNTcxNDA4OTQ3OGEzMjdmMDkxOTc5ODdmMTZmOWU1ZDkzNmU4YSNrZXktMSJ9`.
         *
         */
    export interface AccountSignInput {
      accountId?: /**
             * AccountId
             * example:
             * m/44'/60'/0'/0/2
             */
      AccountId
      messageToSign: /* AccountSignInputMessageToSign */ AccountSignInputMessageToSign
      output?: 'raw' | 'jws'
    }
    /**
         * AccountSignInputMessageToSign
         */
    export type AccountSignInputMessageToSign = /* AccountSignInputMessageToSign */ {
      [name: string]: any
    } | string /* ^[A-Za-z0-9_-]+$ */
    /**
         * AccountSignOutput
         */
    export type AccountSignOutput = /* AccountSignOutput */ /**
         * JWSFlattenedJSON
         * A JWS with flattened JSON serialization. Optional unprotected header properties are not implemented
         * example:
         * {
         *   "payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
         *   "protected": "eyJhbGciOiJFUzI1NiJ9",
         *   "header": {
         *     "kid": "e9bc097a-ce51-4036-9562-d2ade882db0d"
         *   },
         *   "signature": "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
         * }
         */
        JWSFlattenedJSON | string /* ^[A-Za-z0-9_-]+$ */
        /**
         * AccountType
         */
    export type AccountType = 'Identity' | 'Secret'
    /**
         * AccountVerifyInput
         * An object containing:
         * - `accountId`: [OPTIONAL] if accountId is set, it will be used; otherwise, the end user will have to interactively select one account.
         * - `signature`: either a JWS JSON serialized object or a base64url-encoded binary stream
         *
         */
    export interface AccountVerifyInput {
      accountId?: /**
             * AccountId
             * example:
             * m/44'/60'/0'/0/2
             */
      AccountId
      signature: /* Signature */ Signature
    }
    /**
         * AccountVerifyOutput
         * whether the signature was properly verified (true) or not (false).
         */
    export interface AccountVerifyOutput {
      verified: boolean
    }
    /**
         * The "alg" (algorithm) parameter identifies the algorithm intended for use with the key. In JWE is a header parameter that identifies the cryptographic algorithm used to encrypt or determine the value of the CEK.
         *
         * The values used should either be registered in the IANA "JSON Web Signature and Encryption Algorithms" registry established by [JWA]((http://www.rfc-editor.org/info/rfc7518)) or be a value that contains a Collision-Resistant Name. The "alg" value is a case-sensitive ASCII string.
         *
         * example:
         * ES256
         */
    export type Alg = string
    /**
         * Error
         */
    export interface ApiError {
      code: number // int32
      message: string
    }
    /**
         * The "crit" (critical) Header Parameter indicates that extensions to this specification and/or [JWA] are being used that MUST be understood and processed.
         *
         * Its value is an array listing the Header Parameter names present in the JOSE Header that use those extensions. If any of the listed extension Header Parameters are not understood and supported by the recipient, then the JWS is invalid. Producers MUST NOT include Header Parameter names defined by this specification or [JWA] for use with JWS, duplicate names, or names that do not occur as Header Parameter names within the JOSE Header in the "crit" list.  Producers MUST NOT use the empty list "[]" as the "crit" value. Recipients MAY consider the JWS to be invalid if the critical list contains any Header Parameter names defined by this specification or [JWA] for use with JWS or if any other constraints on its use are violated.  When used, this Header Parameter MUST be integrity protected; therefore, it MUST occur only within the JWS Protected Header.
         *
         * This Header Parameter MUST be understood and processed by implementations.
         *
         * An example use, along with a hypothetical "exp" (expiration time) field is:
         *   {"alg":"ES256",
         *     "crit":["exp"],
         *     "exp":1363284000
         *   }
         *
         * example:
         * [
         *   "exp"
         * ]
         */
    export type Crit = string[]
    /**
         * The "cty" (content type) Header Parameter is used by JWS applications to the media type [IANA.MediaTypes] of the secured content (the payload).  This is intended for use by the application when more than one kind of object could be present in the JWS Payload; the application can use this value to disambiguate among the different kinds of objects that might be present. It will typically not be used by applications when the kind of object is already known. This parameter is ignored by JWS implementations; any processing of this parameter is performed by the JWS application.
         *
         * Per RFC 2045 [RFC2045], all media type values, subtype values, and parameter names are case insensitive. However, parameter values are case sensitive unless otherwise specified for the specific parameter.
         *
         * To keep messages compact in common situations, it is RECOMMENDED that producers omit an "application/" prefix of a media type value in a "cty" Header Parameter when no other '/' appears in the media type value.  A recipient using the media type value MUST treat it as if "application/" were prepended to any "cty" value not containing a '/'.  For instance, a "cty" value of "example" SHOULD be used to represent the "application/example" media type, whereas the media type "application/example;part="1/2"" cannot be shortened to "example;part="1/2"".
         *
         */
    export type Cty = string
    /**
         * DID
         * example:
         * did:ethr:rinkeby:0x031bee96cfae8bad99ea0dd3d08d1a3296084f894e9ddfe1ffe141133e81ac5863
         */
    export type Did = string
    /**
         * The "enc" (encryption algorithm) Header Parameter identifies the content encryption algorithm used to perform authenticated encryption on the plaintext to produce the ciphertext and the Authentication Tag. This algorithm MUST be an AEAD algorithm with a specified key length. The encrypted content is not usable if the "enc" value does not represent a supported algorithm. "enc" values should either be registered in the IANA "JSON Web Signature and Encryption Algorithms" registry established by [JWA] or be a value that contains a Collision-Resistant Name.  The "enc" value is a case-sensitive ASCII string containing a StringOrURI value. This Header Parameter MUST be present and MUST be understood and processed by implementations.
         *
         * A list of defined "enc" values for this use can be found in the IANA "JSON Web Signature and Encryption Algorithms" registry established by [JWA]; the initial contents of this registry are the values defined in Section 5.1 of [JWA].
         *
         * example:
         * A256GCM
         */
    export type Enc = string
    /**
         * Identity
         */
    export interface Identity {
      [name: string]: any
      id: /**
             * AccountId
             * example:
             * m/44'/60'/0'/0/2
             */
      AccountId
      name?: string
      description?: string
      type?: /* AccountType */ AccountType
      key?: /**
             * JWK
             * example:
             * {
             *   "kty": "EC",
             *   "crv": "P-256",
             *   "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
             *   "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
             *   "kid": "12"
             * }
             */
      JWK
      /**
             * example:
             * {
             *   "alg": "RSA",
             *   "mod": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
             *   "exp": "AQAB",
             *   "kid": "2011-04-29"
             * }
             */
      publicKey?: any
    }
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
         * JWEFlattenedJSON
         * The flattened JWE JSON Serialization syntax is based upon the general syntax, but flattens it, optimizing it for the single-recipient case. It flattens it by removing the "recipients" member and instead placing those members defined for use in the "recipients" array (the "header" and "encrypted_key" members) in the top-level JSON object (at the same level as the "ciphertext" member).
         *
         * The "recipients" member MUST NOT be present when using this syntax. Other than this syntax difference, JWE JSON Serialization objects using the flattened syntax are processed identically to those using the general syntax.
         *
         * In summary, the syntax of a JWE using the flattened JWE JSON
         *
         * Serialization is as follows:
         *   {
         *     "protected":"<integrity-protected header contents>",
         *     "unprotected":<non-integrity-protected header contents>,
         *     "header":<more non-integrity-protected header contents>,
         *     "encrypted_key":"<encrypted key contents>",
         *     "aad":"<additional authenticated data contents>",
         *     "iv":"<initialization vector contents>",
         *     "ciphertext":"<ciphertext contents>",
         *     "tag":"<authentication tag contents>"
         *   }
         *
         * Note that when using the flattened syntax, just as when using the
         * general syntax, any unprotected Header Parameter values can reside in
         * either the "unprotected" member or the "header" member, or in both.
         *
         * example:
         * {
         *   "protected": "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
         *   "unprotected": {
         *     "jku": "https://server.example.com/keys.jwks"
         *   },
         *   "header": {
         *     "alg": "A128KW",
         *     "kid": "7"
         *   },
         *   "encrypted_key": "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ\"",
         *   "iv": "AxY8DCtDaGlsbGljb3RoZQ",
         *   "ciphertext": "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY\"",
         *   "tag": "Mz-VPPyU4RlcuYv1IwIvzw"
         * }
         */
    export interface JWEFlattenedJSON {
      /**
             * BASE64URL(UTF8(JWE Protected Header))
             *
             * The JWE Protected Header declares:
             *   - `alg`: algorithm to encrypt a fresh and randomly generated Content Encryption Key (CEK) `encrypted_key`
             *   - `enc`: the content encryption algorithm. It should be a symmetric Authenticated Encryption with Associated Data (AEAD) algorithm. Contents will we encrypted using `enc` algorithm with the `encrypted_key`
             *   - `kid`: an identifier of the key that shold be used to decrypt the `encrypted_key`
             *
             * The "protected" member MUST be present and contain the value BASE64URL(UTF8(JWE Protected Header)) when the JWE Protected Header value is non-empty; otherwise, it MUST be absent. These Header Parameter values are integrity protected.
             *
             * An example JWE Protected header is:
             * `{"alg":"ES256","enc":"A256GCM","kid":"did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#key-1"}`
             *
             * example:
             * eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiRVMyNTYiLCJraWQiOiJkaWQ6ZXRocjoweGI5YzU3MTQwODk0NzhhMzI3ZjA5MTk3OTg3ZjE2ZjllNWQ5MzZlOGEja2V5LTEifQ
             */
      protected?: string // ^[A-Za-z0-9_-]+$
      /**
             * JWE Unprotected Header
             *
             * Non-integrity-protected header contents
             *
             * The "unprotected" member MUST be present and contain the value JWE Shared Unprotected Header when the JWE Shared Unprotected Header value is non-empty; otherwise, it MUST be absent. This value is represented as an unencoded JSON object, rather than as a string. These Header Parameter values are not integrity protected.
             *
             */
      unprotected?: {
        [name: string]: any
      }
      /**
             * More non-integrity-protected header contents
             *
             * The "header" member MUST be present and contain the value JWE Per-Recipient Unprotected Header when the JWE Per-Recipient Unprotected Header value is non-empty; otherwise, it MUST be absent. This value is represented as an unencoded JSON object, rather than as a string. These Header Parameter values are not integrity protected.
             *
             */
      header?: {
        [name: string]: any
        alg?: /**
                 * The "alg" (algorithm) parameter identifies the algorithm intended for use with the key. In JWE is a header parameter that identifies the cryptographic algorithm used to encrypt or determine the value of the CEK.
                 *
                 * The values used should either be registered in the IANA "JSON Web Signature and Encryption Algorithms" registry established by [JWA]((http://www.rfc-editor.org/info/rfc7518)) or be a value that contains a Collision-Resistant Name. The "alg" value is a case-sensitive ASCII string.
                 *
                 * example:
                 * ES256
                 */
        Alg
        enc?: /**
                 * The "enc" (encryption algorithm) Header Parameter identifies the content encryption algorithm used to perform authenticated encryption on the plaintext to produce the ciphertext and the Authentication Tag. This algorithm MUST be an AEAD algorithm with a specified key length. The encrypted content is not usable if the "enc" value does not represent a supported algorithm. "enc" values should either be registered in the IANA "JSON Web Signature and Encryption Algorithms" registry established by [JWA] or be a value that contains a Collision-Resistant Name.  The "enc" value is a case-sensitive ASCII string containing a StringOrURI value. This Header Parameter MUST be present and MUST be understood and processed by implementations.
                 *
                 * A list of defined "enc" values for this use can be found in the IANA "JSON Web Signature and Encryption Algorithms" registry established by [JWA]; the initial contents of this registry are the values defined in Section 5.1 of [JWA].
                 *
                 * example:
                 * A256GCM
                 */
        Enc
        zip?: /**
                 * The "zip" (compression algorithm) applied to the plaintext before encryption, if any. The "zip" value defined by RFC7516 specification is "DEF" (Compression with the DEFLATE [RFC1951] algorithm) although other values MAY be used. Compression algorithm values can be registered in the IANA "JSON Web Encryption Compression Algorithms" registry established by [JWA]. The "zip" value is a case-sensitive string.  If no "zip" parameter is present, no compression is applied to the plaintext before encryption. When used, this Header Parameter MUST be integrity protected; therefore, it MUST occur only within the JWE Protected Header. Use of this Header Parameter is OPTIONAL. This Header Parameter MUST be understood and processed by implementations.
                 *
                 */
        Zip
        jku?: /**
                 * The "jku" (JWK Set URL) is a URI [RFC3986] that refers to a resource for a set of JSON-encoded public keys, one of which corresponds to the key used to digitally sign the JWS. The keys MUST be encoded as a JWK Set [JWK]. The protocol used to acquire the resource MUST provide integrity protection; an HTTP GET request to retrieve the JWK Set MUST use Transport Layer Security (TLS) [RFC2818] [RFC5246]; and the identity of the server MUST be validated, as per Section 6 of RFC 6125 [RFC6125]. Also, see Section 8 on TLS requirements.
                 *
                 */
        Jku /* uri */
        jwk?: /**
                 * The "jwk" (JSON Web Key) when in a JWS header is the public key that corresponds to the key used to digitally sign the JWS. This key is represented as a JSON Web Key [JWK]
                 *
                 */
        Jwk /* ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ */
        kid?: /**
                 * The "kid" (key ID) parameter is used to match a specific key. This is used, for instance, to choose among a set of keys within a JWK Set during key rollover.  The structure of the "kid" value is unspecified.  When "kid" values are used within a JWK Set, different keys within the JWK Set SHOULD use distinct "kid" values.  (One example in which different keys might use the same "kid" value is if they have different "kty" (key type) values but are considered to be equivalent alternatives by the application using them.) The "kid" value is a case-sensitive string. When used with JWS or JWE, the "kid" value is used to match a JWS or JWE "kid" Header Parameter value.
                 *
                 * example:
                 * ES256
                 */
        Kid
        x5u?: /**
                 * The "x5u" (X.509 URL) parameter is a URI [RFC3986] that refers to a resource for an X.509 public key certificate or certificate chain [RFC5280]
                 *
                 */
        X5u
        x5c?: /**
                 * The "x5c" (X.509 certificate chain) parameter contains a chain of one or more PKIX certificates [RFC5280].
                 *
                 */
        X5c
        x5t?: /**
                 * The "x5t" (X.509 certificate SHA-1 thumbprint) parameter is a base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate [RFC5280].  Note that certificate thumbprints are also sometimes known as certificate fingerprints. The key in the certificate MUST match the public key represented by other members of the JWK.
                 *
                 */
        X5t
        'x5t#S256'?: /**
                 * x5t#S256
                 * The "x5t#S256" (X.509 certificate SHA-256 thumbprint) parameter is a base64url-encoded SHA-256 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate [RFC5280].  Note that certificate thumbprints are also sometimes known as certificate fingerprints. The key in the certificate MUST match the public key represented by other members of the JWK.
                 *
                 */
        X5tS256
        typ?: /**
                 * The "typ" (type) Header Parameter is used by JWS applications to the media type [IANA.MediaTypes] of this complete JWS. This is intended for use by the application when more than one kind of object could be present in an application data structure that can contain a JWS; the application can use this value to disambiguate among the different kinds of objects that might be present. It will typically not be used by applications when the kind of object is already known. This parameter is ignored by JWS implementations; any processing of this parameter is performed by the JWS application.
                 *
                 * Per RFC 2045 [RFC2045], all media type values, subtype values, and parameter names are case insensitive.  However, parameter values are
                 * case sensitive unless otherwise specified for the specific parameter. To keep messages compact in common situations, it is RECOMMENDED that
                 * producers omit an "application/" prefix of a media type value in a "typ" Header Parameter when no other '/' appears in the media type value. A recipient using the media type value MUST treat it as if "application/" were prepended to any "typ" value not containing a '/'.  For instance, a "typ" value of "example" SHOULD be used to represent the "application/example" media type, whereas the media type "application/example;part="1/2"" cannot be shortened to
                 * "example;part="1/2"".
                 *
                 * The "typ" value "JOSE" can be used by applications to indicate that this object is a JWS or JWE using the JWS Compact Serialization or the JWE Compact Serialization. The "typ" value "JOSE+JSON" can be used by applications to indicate that this object is a JWS or JWE using the JWS JSON Serialization or the JWE JSON Serialization. Other type values can also be used by applications.
                 *
                 * example:
                 * JOSE+JSON
                 */
        Typ
        cty?: /**
                 * The "cty" (content type) Header Parameter is used by JWS applications to the media type [IANA.MediaTypes] of the secured content (the payload).  This is intended for use by the application when more than one kind of object could be present in the JWS Payload; the application can use this value to disambiguate among the different kinds of objects that might be present. It will typically not be used by applications when the kind of object is already known. This parameter is ignored by JWS implementations; any processing of this parameter is performed by the JWS application.
                 *
                 * Per RFC 2045 [RFC2045], all media type values, subtype values, and parameter names are case insensitive. However, parameter values are case sensitive unless otherwise specified for the specific parameter.
                 *
                 * To keep messages compact in common situations, it is RECOMMENDED that producers omit an "application/" prefix of a media type value in a "cty" Header Parameter when no other '/' appears in the media type value.  A recipient using the media type value MUST treat it as if "application/" were prepended to any "cty" value not containing a '/'.  For instance, a "cty" value of "example" SHOULD be used to represent the "application/example" media type, whereas the media type "application/example;part="1/2"" cannot be shortened to "example;part="1/2"".
                 *
                 */
        Cty
        crit?: /**
                 * The "crit" (critical) Header Parameter indicates that extensions to this specification and/or [JWA] are being used that MUST be understood and processed.
                 *
                 * Its value is an array listing the Header Parameter names present in the JOSE Header that use those extensions. If any of the listed extension Header Parameters are not understood and supported by the recipient, then the JWS is invalid. Producers MUST NOT include Header Parameter names defined by this specification or [JWA] for use with JWS, duplicate names, or names that do not occur as Header Parameter names within the JOSE Header in the "crit" list.  Producers MUST NOT use the empty list "[]" as the "crit" value. Recipients MAY consider the JWS to be invalid if the critical list contains any Header Parameter names defined by this specification or [JWA] for use with JWS or if any other constraints on its use are violated.  When used, this Header Parameter MUST be integrity protected; therefore, it MUST occur only within the JWS Protected Header.
                 *
                 * This Header Parameter MUST be understood and processed by implementations.
                 *
                 * An example use, along with a hypothetical "exp" (expiration time) field is:
                 *   {"alg":"ES256",
                 *     "crit":["exp"],
                 *     "exp":1363284000
                 *   }
                 *
                 * example:
                 * [
                 *   "exp"
                 * ]
                 */
        Crit
      }
      /**
             * BASE64URL(JWE Encrypted Key)
             * It should be decrypted with the key identified in the `kid` protected header parameter. Once decrypted, it can be used to decrypt the `ciphertext`
             *
             */
      encrypted_key?: string // ^[A-Za-z0-9_-]+$
      /**
             * OPTIONAL. BASE64URL(JWE additional Authenticated Data contents). A JWE AAD value can be included to supply a base64url-encoded value to be integrity protected but not encrypted.
             *
             */
      aad?: string // ^[A-Za-z0-9_-]+$
      /**
             * OPTIONAL. BASE64URL(JWE Initialization Vector)
             * Initialization Vector value used when encrypting the plaintext
             *
             */
      iv?: string // ^[A-Za-z0-9_-]+$
      /**
             * BASE64URL(JWE Ciphertext)
             */
      ciphertext?: string // ^[A-Za-z0-9_-]+$
      /**
             * OPTIONAL. BASE64URL(JWE Authentication Tag)
             * An output of an AEAD operation that ensures the integrity of the ciphertext and the Additional Authenticated Data.  Note that some algorithms may not use an Authentication Tag, in which case this value is the empty octet sequence.
             *
             */
      tag?: string // ^[A-Za-z0-9_-]+$
    }
    /**
         * JWK
         * example:
         * {
         *   "kty": "EC",
         *   "crv": "P-256",
         *   "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
         *   "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
         *   "kid": "12"
         * }
         */
    export interface JWK {
      [name: string]: any
      kty?: /**
             * The "kty" (key type) parameter identifies the cryptographic algorithm family used with the key, such as "RSA" or "EC".  "kty" values should either be registered in the IANA "JSON Web Key Types" registry established by [JWA](http://www.rfc-editor.org/info/rfc7518) or be a value that contains a Collision-Resistant Name.  The "kty" value is a case-sensitive string. This member MUST be present in a JWK.
             *
             * A list of defined "kty" values can be found in the IANA "JSON Web Key Types" registry established by [JWA]; the initial contents of this registry are the values defined in Section 6.1 of [JWA](http://www.rfc-editor.org/info/rfc7518).
             *
             * The key type definitions include specification of the members to be used for those key types.  Members used with specific "kty" values can be found in the IANA "JSON Web Key Parameters" registry.
             *
             * example:
             * EC
             */
      Kty
      use?: /**
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
      Use
      key_ops?: /**
             * The "key_ops" (key operations) parameter identifies the operation(s) for which the key is intended to be used.  The "key_ops" parameter is intended for use cases in which public, private, or symmetric keys may be present.
             *
             * Its value is an array of key operation values.  Values defined by this specification are:
             * - "sign" (compute digital signature or MAC)
             * - "verify" (verify digital signature or MAC)
             * - "encrypt" (encrypt content)
             * - "decrypt" (decrypt content and validate decryption, if applicable)
             * - "wrapKey" (encrypt key)
             * - "unwrapKey" (decrypt key and validate decryption, if applicable)
             * - "deriveKey" (derive key)
             * - "deriveBits" (derive bits not to be used as a key)
             *
             * (Note that the "key_ops" values intentionally match the "KeyUsage" values defined in the Web Cryptography API specification.)
             *
             * Other values MAY be used.  The key operation values are case-sensitive strings.  Duplicate key operation values MUST NOT be present in the array.
             *
             * example:
             * [
             *   "sign",
             *   "decrypt"
             * ]
             */
      KeyOps
      alg?: /**
             * The "alg" (algorithm) parameter identifies the algorithm intended for use with the key. In JWE is a header parameter that identifies the cryptographic algorithm used to encrypt or determine the value of the CEK.
             *
             * The values used should either be registered in the IANA "JSON Web Signature and Encryption Algorithms" registry established by [JWA]((http://www.rfc-editor.org/info/rfc7518)) or be a value that contains a Collision-Resistant Name. The "alg" value is a case-sensitive ASCII string.
             *
             * example:
             * ES256
             */
      Alg
      kid?: /**
             * The "kid" (key ID) parameter is used to match a specific key. This is used, for instance, to choose among a set of keys within a JWK Set during key rollover.  The structure of the "kid" value is unspecified.  When "kid" values are used within a JWK Set, different keys within the JWK Set SHOULD use distinct "kid" values.  (One example in which different keys might use the same "kid" value is if they have different "kty" (key type) values but are considered to be equivalent alternatives by the application using them.) The "kid" value is a case-sensitive string. When used with JWS or JWE, the "kid" value is used to match a JWS or JWE "kid" Header Parameter value.
             *
             * example:
             * ES256
             */
      Kid
      x5u?: /**
             * The "x5u" (X.509 URL) parameter is a URI [RFC3986] that refers to a resource for an X.509 public key certificate or certificate chain [RFC5280]
             *
             */
      X5u
      x5c?: /**
             * The "x5c" (X.509 certificate chain) parameter contains a chain of one or more PKIX certificates [RFC5280].
             *
             */
      X5c
      x5t?: /**
             * The "x5t" (X.509 certificate SHA-1 thumbprint) parameter is a base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate [RFC5280].  Note that certificate thumbprints are also sometimes known as certificate fingerprints. The key in the certificate MUST match the public key represented by other members of the JWK.
             *
             */
      X5t
      'x5t#S256'?: /**
             * x5t#S256
             * The "x5t#S256" (X.509 certificate SHA-256 thumbprint) parameter is a base64url-encoded SHA-256 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate [RFC5280].  Note that certificate thumbprints are also sometimes known as certificate fingerprints. The key in the certificate MUST match the public key represented by other members of the JWK.
             *
             */
      X5tS256
    }
    /**
         * JWSFlattenedJSON
         * A JWS with flattened JSON serialization. Optional unprotected header properties are not implemented
         * example:
         * {
         *   "payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
         *   "protected": "eyJhbGciOiJFUzI1NiJ9",
         *   "header": {
         *     "kid": "e9bc097a-ce51-4036-9562-d2ade882db0d"
         *   },
         *   "signature": "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
         * }
         */
    export interface JWSFlattenedJSON {
      /**
             * Base64Url encoded of the JWS Protected Headers: BASE64URL(UTF8(JWS Protected Header)).
             *
             * The JWS Protected Header declares that the encoded object is a JSON Web Token (`"typ"="JWT"`), the signature algorithm `alg`, and and identifier of the verification key (`kid`)
             *
             * Examples values for `alg` could be:
             *   - `HS256`: HMAC using SHA-256 hash algorithm
             *   - `HS384`: HMAC using SHA-384 hash algorithm
             *   - `HS512`: HMAC using SHA-512 hash algorithm
             *   - `ES256`: ECDSA using P-256 curve and SHA-256 hash algorithm
             *   - `ES384`: ECDSA using P-384 curve and SHA-384 hash algorithm
             *   - `ES512`: ECDSA using P-521 curve and SHA-512 hash algorithm
             *
             * An example JWS Protected header is:
             * `{"typ":"JWT","alg":"ES256","kid":"did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#key-1"}`
             *
             * example:
             * eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDpldGhyOjB4YjljNTcxNDA4OTQ3OGEzMjdmMDkxOTc5ODdmMTZmOWU1ZDkzNmU4YSNrZXktMSJ9
             */
      protected: string // ^[A-Za-z0-9_-]+$
      /**
             * For a JWS, the members of the JSON object(s) representing the JOSE Header describe the digital signature or MAC applied to the JWS Protected Header and the JWS Payload and optionally additional properties of the JWS. The Header Parameter names within the JOSE Header MUST be unique; JWS parsers MUST either reject JWSs with duplicate Header Parameter names or use a JSON parser that returns only the lexically last duplicate member name, as specified in Section 15.12 ("The JSON Object") of ECMAScript 5.1 [ECMAScript].
             *
             * Implementations are required to understand the specific Header Parameters defined by this specification that are designated as "MUST be understood" and process them in the manner defined in this specification.  All other Header Parameters defined by this specification that are not so designated MUST be ignored when not understood.  Unless listed as a critical Header Parameter, per   Section 4.1.11, all Header Parameters not defined by this specification MUST be ignored when not understood.
             *
             * example:
             * {
             *   "kid": "e9bc097a-ce51-4036-9562-d2ade882db0d"
             * }
             */
      header?: {
        [name: string]: any
        alg?: /**
                 * The "alg" (algorithm) parameter identifies the algorithm intended for use with the key. In JWE is a header parameter that identifies the cryptographic algorithm used to encrypt or determine the value of the CEK.
                 *
                 * The values used should either be registered in the IANA "JSON Web Signature and Encryption Algorithms" registry established by [JWA]((http://www.rfc-editor.org/info/rfc7518)) or be a value that contains a Collision-Resistant Name. The "alg" value is a case-sensitive ASCII string.
                 *
                 * example:
                 * ES256
                 */
        Alg
        jku?: /**
                 * The "jku" (JWK Set URL) is a URI [RFC3986] that refers to a resource for a set of JSON-encoded public keys, one of which corresponds to the key used to digitally sign the JWS. The keys MUST be encoded as a JWK Set [JWK]. The protocol used to acquire the resource MUST provide integrity protection; an HTTP GET request to retrieve the JWK Set MUST use Transport Layer Security (TLS) [RFC2818] [RFC5246]; and the identity of the server MUST be validated, as per Section 6 of RFC 6125 [RFC6125]. Also, see Section 8 on TLS requirements.
                 *
                 */
        Jku /* uri */
        jwk?: /**
                 * The "jwk" (JSON Web Key) when in a JWS header is the public key that corresponds to the key used to digitally sign the JWS. This key is represented as a JSON Web Key [JWK]
                 *
                 */
        Jwk /* ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ */
        kid?: /**
                 * The "kid" (key ID) parameter is used to match a specific key. This is used, for instance, to choose among a set of keys within a JWK Set during key rollover.  The structure of the "kid" value is unspecified.  When "kid" values are used within a JWK Set, different keys within the JWK Set SHOULD use distinct "kid" values.  (One example in which different keys might use the same "kid" value is if they have different "kty" (key type) values but are considered to be equivalent alternatives by the application using them.) The "kid" value is a case-sensitive string. When used with JWS or JWE, the "kid" value is used to match a JWS or JWE "kid" Header Parameter value.
                 *
                 * example:
                 * ES256
                 */
        Kid
        x5u?: /**
                 * The "x5u" (X.509 URL) parameter is a URI [RFC3986] that refers to a resource for an X.509 public key certificate or certificate chain [RFC5280]
                 *
                 */
        X5u
        x5c?: /**
                 * The "x5c" (X.509 certificate chain) parameter contains a chain of one or more PKIX certificates [RFC5280].
                 *
                 */
        X5c
        x5t?: /**
                 * The "x5t" (X.509 certificate SHA-1 thumbprint) parameter is a base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate [RFC5280].  Note that certificate thumbprints are also sometimes known as certificate fingerprints. The key in the certificate MUST match the public key represented by other members of the JWK.
                 *
                 */
        X5t
        'x5t#S256'?: /**
                 * x5t#S256
                 * The "x5t#S256" (X.509 certificate SHA-256 thumbprint) parameter is a base64url-encoded SHA-256 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate [RFC5280].  Note that certificate thumbprints are also sometimes known as certificate fingerprints. The key in the certificate MUST match the public key represented by other members of the JWK.
                 *
                 */
        X5tS256
        typ?: /**
                 * The "typ" (type) Header Parameter is used by JWS applications to the media type [IANA.MediaTypes] of this complete JWS. This is intended for use by the application when more than one kind of object could be present in an application data structure that can contain a JWS; the application can use this value to disambiguate among the different kinds of objects that might be present. It will typically not be used by applications when the kind of object is already known. This parameter is ignored by JWS implementations; any processing of this parameter is performed by the JWS application.
                 *
                 * Per RFC 2045 [RFC2045], all media type values, subtype values, and parameter names are case insensitive.  However, parameter values are
                 * case sensitive unless otherwise specified for the specific parameter. To keep messages compact in common situations, it is RECOMMENDED that
                 * producers omit an "application/" prefix of a media type value in a "typ" Header Parameter when no other '/' appears in the media type value. A recipient using the media type value MUST treat it as if "application/" were prepended to any "typ" value not containing a '/'.  For instance, a "typ" value of "example" SHOULD be used to represent the "application/example" media type, whereas the media type "application/example;part="1/2"" cannot be shortened to
                 * "example;part="1/2"".
                 *
                 * The "typ" value "JOSE" can be used by applications to indicate that this object is a JWS or JWE using the JWS Compact Serialization or the JWE Compact Serialization. The "typ" value "JOSE+JSON" can be used by applications to indicate that this object is a JWS or JWE using the JWS JSON Serialization or the JWE JSON Serialization. Other type values can also be used by applications.
                 *
                 * example:
                 * JOSE+JSON
                 */
        Typ
        cty?: /**
                 * The "cty" (content type) Header Parameter is used by JWS applications to the media type [IANA.MediaTypes] of the secured content (the payload).  This is intended for use by the application when more than one kind of object could be present in the JWS Payload; the application can use this value to disambiguate among the different kinds of objects that might be present. It will typically not be used by applications when the kind of object is already known. This parameter is ignored by JWS implementations; any processing of this parameter is performed by the JWS application.
                 *
                 * Per RFC 2045 [RFC2045], all media type values, subtype values, and parameter names are case insensitive. However, parameter values are case sensitive unless otherwise specified for the specific parameter.
                 *
                 * To keep messages compact in common situations, it is RECOMMENDED that producers omit an "application/" prefix of a media type value in a "cty" Header Parameter when no other '/' appears in the media type value.  A recipient using the media type value MUST treat it as if "application/" were prepended to any "cty" value not containing a '/'.  For instance, a "cty" value of "example" SHOULD be used to represent the "application/example" media type, whereas the media type "application/example;part="1/2"" cannot be shortened to "example;part="1/2"".
                 *
                 */
        Cty
        crit?: /**
                 * The "crit" (critical) Header Parameter indicates that extensions to this specification and/or [JWA] are being used that MUST be understood and processed.
                 *
                 * Its value is an array listing the Header Parameter names present in the JOSE Header that use those extensions. If any of the listed extension Header Parameters are not understood and supported by the recipient, then the JWS is invalid. Producers MUST NOT include Header Parameter names defined by this specification or [JWA] for use with JWS, duplicate names, or names that do not occur as Header Parameter names within the JOSE Header in the "crit" list.  Producers MUST NOT use the empty list "[]" as the "crit" value. Recipients MAY consider the JWS to be invalid if the critical list contains any Header Parameter names defined by this specification or [JWA] for use with JWS or if any other constraints on its use are violated.  When used, this Header Parameter MUST be integrity protected; therefore, it MUST occur only within the JWS Protected Header.
                 *
                 * This Header Parameter MUST be understood and processed by implementations.
                 *
                 * An example use, along with a hypothetical "exp" (expiration time) field is:
                 *   {"alg":"ES256",
                 *     "crit":["exp"],
                 *     "exp":1363284000
                 *   }
                 *
                 * example:
                 * [
                 *   "exp"
                 * ]
                 */
        Crit
      }
      /**
             * Base64Url encoded of the JWS Pyload: BASE64URL(JWS Payload).
             * The payload is the binary array that it has been signed. It is often a UTF-8 representation of a JSON object that includes the `signed` object along with some other props assigned by the signer.
             *
             * An example payload could be:
             * `{"iss":"did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a","iat":1611076613,"signed":"aTMtbWFya2V0IGlzIHdoYXQgaXQgaXMuIERvIHlvdSBrbm93IHdoYXQgaXMgaXQ_"}`
             *
             * example:
             * eyJpc3MiOiJkaWQ6ZXRocjoweGI5YzU3MTQwODk0NzhhMzI3ZjA5MTk3OTg3ZjE2ZjllNWQ5MzZlOGEiLCJpYXQiOjE2MTEwNzY2MTMsInNpZ25lZCI6ImFUTXRiV0Z5YTJWMElHbHpJSGRvWVhRZ2FYUWdhWE11SUVSdklIbHZkU0JyYm05M0lIZG9ZWFFnYVhNZ2FYUV8ifQ
             */
      payload: string // ^[A-Za-z0-9_-]+$
      /**
             * The signature or HMAC of the JWS Signing Input ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload)) with the algoritm `alg`
             *
             * example:
             * LSOC5nsxpqs3XeRh_uhBbGlF1uqyOxFNmHfUua66Fw0iPM1plHh01V4nVrz10Hq8_6oOowtU9ePKvxPTDYZo4g
             */
      signature: string // ^[A-Za-z0-9_-]+$
    }
    /**
         * The "jku" (JWK Set URL) is a URI [RFC3986] that refers to a resource for a set of JSON-encoded public keys, one of which corresponds to the key used to digitally sign the JWS. The keys MUST be encoded as a JWK Set [JWK]. The protocol used to acquire the resource MUST provide integrity protection; an HTTP GET request to retrieve the JWK Set MUST use Transport Layer Security (TLS) [RFC2818] [RFC5246]; and the identity of the server MUST be validated, as per Section 6 of RFC 6125 [RFC6125]. Also, see Section 8 on TLS requirements.
         *
         */
    export type Jku = string // uri
    /**
         * The "jwk" (JSON Web Key) when in a JWS header is the public key that corresponds to the key used to digitally sign the JWS. This key is represented as a JSON Web Key [JWK]
         *
         */
    export type Jwk = string // ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$
    /**
         * The "key_ops" (key operations) parameter identifies the operation(s) for which the key is intended to be used.  The "key_ops" parameter is intended for use cases in which public, private, or symmetric keys may be present.
         *
         * Its value is an array of key operation values.  Values defined by this specification are:
         * - "sign" (compute digital signature or MAC)
         * - "verify" (verify digital signature or MAC)
         * - "encrypt" (encrypt content)
         * - "decrypt" (decrypt content and validate decryption, if applicable)
         * - "wrapKey" (encrypt key)
         * - "unwrapKey" (decrypt key and validate decryption, if applicable)
         * - "deriveKey" (derive key)
         * - "deriveBits" (derive bits not to be used as a key)
         *
         * (Note that the "key_ops" values intentionally match the "KeyUsage" values defined in the Web Cryptography API specification.)
         *
         * Other values MAY be used.  The key operation values are case-sensitive strings.  Duplicate key operation values MUST NOT be present in the array.
         *
         * example:
         * [
         *   "sign",
         *   "decrypt"
         * ]
         */
    export type KeyOps = string[]
    /**
         * The "kid" (key ID) parameter is used to match a specific key. This is used, for instance, to choose among a set of keys within a JWK Set during key rollover.  The structure of the "kid" value is unspecified.  When "kid" values are used within a JWK Set, different keys within the JWK Set SHOULD use distinct "kid" values.  (One example in which different keys might use the same "kid" value is if they have different "kty" (key type) values but are considered to be equivalent alternatives by the application using them.) The "kid" value is a case-sensitive string. When used with JWS or JWE, the "kid" value is used to match a JWS or JWE "kid" Header Parameter value.
         *
         * example:
         * ES256
         */
    export type Kid = string
    /**
         * The "kty" (key type) parameter identifies the cryptographic algorithm family used with the key, such as "RSA" or "EC".  "kty" values should either be registered in the IANA "JSON Web Key Types" registry established by [JWA](http://www.rfc-editor.org/info/rfc7518) or be a value that contains a Collision-Resistant Name.  The "kty" value is a case-sensitive string. This member MUST be present in a JWK.
         *
         * A list of defined "kty" values can be found in the IANA "JSON Web Key Types" registry established by [JWA]; the initial contents of this registry are the values defined in Section 6.1 of [JWA](http://www.rfc-editor.org/info/rfc7518).
         *
         * The key type definitions include specification of the members to be used for those key types.  Members used with specific "kty" values can be found in the IANA "JSON Web Key Parameters" registry.
         *
         * example:
         * EC
         */
    export type Kty = string
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
         * Secret
         */
    export interface Secret {
      [name: string]: any
      id: /**
             * AccountId
             * example:
             * m/44'/60'/0'/0/2
             */
      AccountId
      name?: string
      description?: string
      type?: /* AccountType */ AccountType
      key?: /**
             * JWK
             * example:
             * {
             *   "kty": "EC",
             *   "crv": "P-256",
             *   "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
             *   "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
             *   "kid": "12"
             * }
             */
      JWK
    }
    /**
         * Signature
         */
    export type Signature = /* Signature */ /**
         * JWSFlattenedJSON
         * A JWS with flattened JSON serialization. Optional unprotected header properties are not implemented
         * example:
         * {
         *   "payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
         *   "protected": "eyJhbGciOiJFUzI1NiJ9",
         *   "header": {
         *     "kid": "e9bc097a-ce51-4036-9562-d2ade882db0d"
         *   },
         *   "signature": "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
         * }
         */
        JWSFlattenedJSON | string /* ^[A-Za-z0-9_-]+$ */
        /**
         * The "typ" (type) Header Parameter is used by JWS applications to the media type [IANA.MediaTypes] of this complete JWS. This is intended for use by the application when more than one kind of object could be present in an application data structure that can contain a JWS; the application can use this value to disambiguate among the different kinds of objects that might be present. It will typically not be used by applications when the kind of object is already known. This parameter is ignored by JWS implementations; any processing of this parameter is performed by the JWS application.
         *
         * Per RFC 2045 [RFC2045], all media type values, subtype values, and parameter names are case insensitive.  However, parameter values are
         * case sensitive unless otherwise specified for the specific parameter. To keep messages compact in common situations, it is RECOMMENDED that
         * producers omit an "application/" prefix of a media type value in a "typ" Header Parameter when no other '/' appears in the media type value. A recipient using the media type value MUST treat it as if "application/" were prepended to any "typ" value not containing a '/'.  For instance, a "typ" value of "example" SHOULD be used to represent the "application/example" media type, whereas the media type "application/example;part="1/2"" cannot be shortened to
         * "example;part="1/2"".
         *
         * The "typ" value "JOSE" can be used by applications to indicate that this object is a JWS or JWE using the JWS Compact Serialization or the JWE Compact Serialization. The "typ" value "JOSE+JSON" can be used by applications to indicate that this object is a JWS or JWE using the JWS JSON Serialization or the JWE JSON Serialization. Other type values can also be used by applications.
         *
         * example:
         * JOSE+JSON
         */
    export type Typ = string
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
    export type Use = string
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
         * The "x5c" (X.509 certificate chain) parameter contains a chain of one or more PKIX certificates [RFC5280].
         *
         */
    export type X5c = string[]
    /**
         * The "x5t" (X.509 certificate SHA-1 thumbprint) parameter is a base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate [RFC5280].  Note that certificate thumbprints are also sometimes known as certificate fingerprints. The key in the certificate MUST match the public key represented by other members of the JWK.
         *
         */
    export type X5t = string
    /**
         * x5t#S256
         * The "x5t#S256" (X.509 certificate SHA-256 thumbprint) parameter is a base64url-encoded SHA-256 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate [RFC5280].  Note that certificate thumbprints are also sometimes known as certificate fingerprints. The key in the certificate MUST match the public key represented by other members of the JWK.
         *
         */
    export type X5tS256 = string
    /**
         * The "x5u" (X.509 URL) parameter is a URI [RFC3986] that refers to a resource for an X.509 public key certificate or certificate chain [RFC5280]
         *
         */
    export type X5u = string
    /**
         * The "zip" (compression algorithm) applied to the plaintext before encryption, if any. The "zip" value defined by RFC7516 specification is "DEF" (Compression with the DEFLATE [RFC1951] algorithm) although other values MAY be used. Compression algorithm values can be registered in the IANA "JSON Web Encryption Compression Algorithms" registry established by [JWA]. The "zip" value is a case-sensitive string.  If no "zip" parameter is present, no compression is applied to the plaintext before encryption. When used, this Header Parameter MUST be integrity protected; therefore, it MUST occur only within the JWE Protected Header. Use of this Header Parameter is OPTIONAL. This Header Parameter MUST be understood and processed by implementations.
         *
         */
    export type Zip = string
  }
}
export namespace WalletPaths {
  export namespace AccountCreate {
    export type RequestBody = /**
         * AccountCreateInput
         * Besides the here defined options, provider specific properties should be added here if necessary, e.g. "path" for BIP21 wallets, or the key algorithm (if the wallet supports multiple algorithm).
         *
         */
        WalletComponents.Schemas.AccountCreateInput
    export namespace Responses {
      export type $201 = /**
             * AccountCreateOutput
             * It returns the account id and type
             *
             */
            WalletComponents.Schemas.AccountCreateOutput
      export type Default = /* Error */ WalletComponents.Schemas.ApiError
    }
  }
  export namespace AccountDecrypt {
    export type RequestBody = /**
         * AccountDecryptInput
         * An object containing:
         * - `accountId`: [OPTIONAL] if accountId is set, it will be used; otherwise, the end user will have to interactively select one account.
         * - `ciphertext`: an object containing base64url-encoded versions of the ciphertext, and the iv used to encrypt it (if used).
         *
         */
        WalletComponents.Schemas.AccountDecryptInput
    export namespace Responses {
      export type $200 = /**
             * AccountDecryptOutput
             * The decrypted message Base64Url
             */
            WalletComponents.Schemas.AccountDecryptOutput /* ^[A-Za-z0-9_-]+$ */
      export type Default = /* Error */ WalletComponents.Schemas.ApiError
    }
  }
  export namespace AccountEncrypt {
    export type RequestBody = /**
         * AccountEncryptInput
         * An object containing:
         * - `accountId`: [OPTIONAL] if accountId is set, it will be used; otherwise, the end user will have to interactively select one account.
         * - `input`: base64url-encoded versions of the plaintext to encrypt, and an optional iv (random one will be chosen if not provided).
         *
         */
        WalletComponents.Schemas.AccountEncryptInput
    export namespace Responses {
      export type $200 = /**
             * AccountEncryptOutput
             * The flattened JWE JSON Serialization syntax is based upon the general syntax, but flattens it, optimizing it for the single-recipient case. It flattens it by removing the "recipients" member and instead placing those members defined for use in the "recipients" array (the "header" and "encrypted_key" members) in the top-level JSON object (at the same level as the "ciphertext" member).
             *
             * The "recipients" member MUST NOT be present when using this syntax. Other than this syntax difference, JWE JSON Serialization objects using the flattened syntax are processed identically to those using the general syntax.
             *
             * In summary, the syntax of a JWE using the flattened JWE JSON
             *
             * Serialization is as follows:
             *   {
             *     "protected":"<integrity-protected header contents>",
             *     "unprotected":<non-integrity-protected header contents>,
             *     "header":<more non-integrity-protected header contents>,
             *     "encrypted_key":"<encrypted key contents>",
             *     "aad":"<additional authenticated data contents>",
             *     "iv":"<initialization vector contents>",
             *     "ciphertext":"<ciphertext contents>",
             *     "tag":"<authentication tag contents>"
             *   }
             *
             * Note that when using the flattened syntax, just as when using the
             * general syntax, any unprotected Header Parameter values can reside in
             * either the "unprotected" member or the "header" member, or in both.
             *
             * example:
             * {
             *   "protected": "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
             *   "unprotected": {
             *     "jku": "https://server.example.com/keys.jwks"
             *   },
             *   "header": {
             *     "alg": "A128KW",
             *     "kid": "7"
             *   },
             *   "encrypted_key": "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ\"",
             *   "iv": "AxY8DCtDaGlsbGljb3RoZQ",
             *   "ciphertext": "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY\"",
             *   "tag": "Mz-VPPyU4RlcuYv1IwIvzw"
             * }
             */
            WalletComponents.Schemas.AccountEncryptOutput
      export type Default = /* Error */ WalletComponents.Schemas.ApiError
    }
  }
  export namespace AccountList {
    export namespace Parameters {
      export type AccountIds = string[]
      export type Props = string[]
    }
    export interface QueryParameters {
      account_ids?: Parameters.AccountIds
      props?: Parameters.Props
    }
    export namespace Responses {
      export type $200 = /* AccountListOutput */ WalletComponents.Schemas.AccountListOutput
      export type Default = /* Error */ WalletComponents.Schemas.ApiError
    }
  }
  export namespace AccountSign {
    export type RequestBody = /**
         * AccountSignInput
         * An object containing:
         * - `accountId`: [OPTIONAL] if accountId is set, it will be used; otherwise, the end user will have to interactively select one account.
         * - `messageToSign`: It can be either an plain object or a string (preferably a BASE64URL). Examples:
         *   `eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDpldGhyOjB4YjljNTcxNDA4OTQ3OGEzMjdmMDkxOTc5ODdmMTZmOWU1ZDkzNmU4YSNrZXktMSJ9`.
         *
         */
        WalletComponents.Schemas.AccountSignInput
    export namespace Responses {
      export type $200 = /* AccountSignOutput */ WalletComponents.Schemas.AccountSignOutput
      export type Default = /* Error */ WalletComponents.Schemas.ApiError
    }
  }
  export namespace AccountVerify {
    export type RequestBody = /**
         * AccountVerifyInput
         * An object containing:
         * - `accountId`: [OPTIONAL] if accountId is set, it will be used; otherwise, the end user will have to interactively select one account.
         * - `signature`: either a JWS JSON serialized object or a base64url-encoded binary stream
         *
         */
        WalletComponents.Schemas.AccountVerifyInput
    export namespace Responses {
      export type $200 = /**
             * AccountVerifyOutput
             * whether the signature was properly verified (true) or not (false).
             */
            WalletComponents.Schemas.AccountVerifyOutput
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
}
