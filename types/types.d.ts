import { ContractInterface } from '@ethersproject/contracts';
import { JWEHeaderParameters, JWK as JWKjose, JWTHeaderParameters } from 'jose';
import { ENC_ALGS, HASH_ALGS, SIGNING_ALGS } from './constants';
export { KeyLike } from 'jose';
export { ContractInterface };
export declare type HashAlg = typeof HASH_ALGS[number];
export declare type SigningAlg = typeof SIGNING_ALGS[number];
export declare type EncryptionAlg = typeof ENC_ALGS[number];
export declare type Dict<T> = T & {
    [key: string | symbol | number]: any | undefined;
};
export interface Algs {
    hashAlg?: HashAlg;
    SigningAlg?: SigningAlg;
    EncAlg?: EncryptionAlg;
}
export interface JWK extends JWKjose {
    alg: SigningAlg | EncryptionAlg;
}
export interface ContractConfig {
    address: string;
    abi: ContractInterface;
}
export interface DltConfig {
    rpcProviderUrl: string;
    gasLimit: number;
    contract: ContractConfig;
}
export interface StoredProof<T extends NrProofPayload> {
    jws: string;
    payload: T;
}
export interface Block {
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
export interface OrigBlock extends Block {
    raw: Uint8Array;
    jwe: string;
    secret: {
        jwk: JWK;
        hex: string;
    };
}
export interface TimestampVerifyOptions {
    timestamp: 'iat' | number;
    notBefore: 'iat' | number;
    notAfter: 'iat' | number;
    tolerance?: number;
}
export interface DataExchangeAgreement {
    orig: string;
    dest: string;
    hashAlg: HashAlg;
    encAlg: EncryptionAlg;
    signingAlg: SigningAlg;
    ledgerContractAddress: string;
    ledgerSignerAddress: string;
    pooToPorDelay: number;
    pooToPopDelay: number;
    pooToSecretDelay: number;
    schema?: string;
}
export interface DataExchange extends DataExchangeAgreement {
    id: string;
    cipherblockDgst: string;
    blockCommitment: string;
    secretCommitment: string;
}
export interface JwkPair {
    publicJwk: JWK;
    privateJwk: JWK;
}
export interface ProofPayload {
    iat: number;
    iss: string;
    proofType: string;
}
export interface NrProofPayload extends ProofPayload {
    exchange: DataExchange;
}
export interface PoOPayload extends NrProofPayload {
    iss: 'orig';
    proofType: 'PoO';
}
export interface PoRPayload extends NrProofPayload {
    iss: 'dest';
    proofType: 'PoR';
    poo: string;
}
export interface PoPPayload extends NrProofPayload {
    iss: 'orig';
    proofType: 'PoP';
    por: string;
    secret: string;
    verificationCode: string;
}
export interface ConflictResolutionRequestPayload extends ProofPayload {
    proofType: 'request';
    iss: 'orig' | 'dest';
    iat: number;
    por: string;
    dataExchangeId: string;
}
export interface VerificationRequestPayload extends ConflictResolutionRequestPayload {
    type: 'verificationRequest';
}
export interface DisputeRequestPayload extends ConflictResolutionRequestPayload {
    type: 'disputeRequest';
    iss: 'dest';
    cipherblock: string;
}
export interface ResolutionPayload extends ProofPayload {
    proofType: 'resolution';
    type?: string;
    resolution?: string;
    dataExchangeId: string;
    iat: number;
    iss: string;
    sub: string;
}
export interface VerificationResolutionPayload extends ResolutionPayload {
    type: 'verification';
    resolution: 'completed' | 'not completed';
}
export interface DisputeResolutionPayload extends ResolutionPayload {
    type: 'dispute';
    resolution: 'accepted' | 'denied';
}
export interface DecodedProof<T extends ProofPayload> {
    header: JWTHeaderParameters;
    payload: T;
    signer?: JWK;
}
export declare type getFromJws<T> = (header: JWEHeaderParameters, payload: T) => Promise<JWK>;
export declare type NrErrorName = 'not a compact jws' | 'invalid key' | 'encryption failed' | 'decryption failed' | 'jws verification failed' | 'invalid algorithm' | 'invalid poo' | 'invalid por' | 'invalid pop' | 'invalid dispute request' | 'invalid verification request' | 'invalid dispute request' | 'data exchange not as expected' | 'dataExchange integrity violated' | 'secret not published' | 'secret not published in time' | 'received too late' | 'unexpected error' | 'invalid timestamp' | 'invalid format' | 'cannot contact the ledger' | 'cannot verify';
//# sourceMappingURL=types.d.ts.map