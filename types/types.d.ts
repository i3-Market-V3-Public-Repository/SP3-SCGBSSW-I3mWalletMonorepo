import { ContractInterface } from '@ethersproject/contracts';
import { JWEHeaderParameters, JWK as JWKjose, JWTHeaderParameters, JWTPayload } from 'jose';
import { DltSigner } from './signers';
export { KeyLike } from 'jose';
export { ContractInterface };
export declare type HashAlg = 'SHA-256' | 'SHA-384' | 'SHA-512';
export declare type SigningAlg = 'ES256' | 'ES384' | 'ES512';
export declare type EncryptionAlg = 'A128GCM' | 'A256GCM';
export declare type Sign<T> = T & {
    [key: string | symbol]: any | undefined;
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
    disable: boolean;
    signer?: DltSigner;
}
export interface StoredProof {
    jws: string;
    payload: ProofPayload;
}
export interface Block {
    raw?: Uint8Array;
    jwe?: string;
    secret?: {
        jwk: JWK;
        hex: string;
    };
    poo?: StoredProof;
    por?: StoredProof;
    pop?: StoredProof;
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
    currentTimestamp?: number;
    expectedTimestampInterval?: {
        min: number;
        max: number;
    };
    clockToleranceMs?: number;
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
export interface ProofInputPayload {
    [key: string]: string | number | DataExchange | undefined;
    exchange: DataExchange;
    iss: string;
    proofType: string;
}
export interface ProofPayload extends ProofInputPayload {
    iat: number;
    iss: 'orig' | 'dest';
}
export interface PoOInputPayload extends ProofInputPayload {
    iss: 'orig';
    proofType: 'PoO';
}
export interface PoOPayload extends PoOInputPayload {
    iat: number;
}
export interface PoRInputPayload extends ProofInputPayload {
    iss: 'dest';
    proofType: 'PoR';
    poo: string;
}
export interface PoRPayload extends PoRInputPayload {
    iat: number;
}
export interface PoPInputPayload extends ProofInputPayload {
    iss: 'orig';
    proofType: 'PoP';
    por: string;
    secret: string;
}
export interface PoPPayload extends PoPInputPayload {
    iat: number;
    verificationCode: string;
}
interface ConflictResolutionRequest extends JWTPayload {
    iss: 'orig' | 'dest';
    iat: number;
    por: string;
    dataExchangeId: string;
}
export interface VerificationRequestPayload extends ConflictResolutionRequest {
    type: 'verificationRequest';
}
export interface DisputeRequestPayload extends ConflictResolutionRequest {
    type: 'disputeRequest';
    iss: 'dest';
    cipherblock: string;
}
export interface Resolution extends JWTPayload {
    type?: string;
    resolution?: string;
    dataExchangeId: string;
    iat: number;
    iss: string;
}
export interface VerificationResolution extends Resolution {
    type: 'verification';
    resolution: 'completed' | 'not completed';
}
export interface DisputeResolution extends Resolution {
    type: 'dispute';
    resolution: 'accepted' | 'denied';
}
export interface JwsHeaderAndPayload<T> {
    header: JWTHeaderParameters;
    payload: T;
}
export declare type getFromJws<T> = (header: JWEHeaderParameters, payload: T) => Promise<JWK>;
export declare type NrErrorName = 'not a compact jws' | 'invalid key' | 'encryption failed' | 'decryption failed' | 'jws verification failed' | 'invalid algorithm' | 'invalid poo' | 'invalid por' | 'invalid pop' | 'invalid dispute request' | 'invalid verification request' | 'invalid dispute request' | 'data exchange not as expected' | 'dataExchange integrity violated' | 'secret not published' | 'secret not published in time' | 'received too late' | 'unexpected error' | 'invalid iat' | 'invalid format' | 'cannot contact the ledger' | 'cannot verify';
//# sourceMappingURL=types.d.ts.map