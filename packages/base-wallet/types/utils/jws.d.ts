/// <reference types="node" />
export interface DecodedJWS {
    header: any;
    payload: any;
    signature: string;
    data: string;
}
/**
 * Prepares header and payload, received as standard JS objects, to be signed as needed for a JWS/JWT signature.
 *
 * @param header
 * @param payload
 * @param encoding
 * @returns <base64url(header)>.<base64url(payload)>
 */
export declare function jwsSignInput(header: object, payload: object, encoding?: BufferEncoding): string;
/**
 * Returns a decoded JWS
 *
 * @param jws
 * @param encoding
 * @returns
 */
export declare function decodeJWS(jws: string, encoding?: BufferEncoding): DecodedJWS;
//# sourceMappingURL=jws.d.ts.map