import { ContractInterface } from '@ethersproject/contracts';
import { JWK as JWKjose } from 'jose';
export { ContractInterface };
export { CompactDecryptResult, JWTVerifyResult } from 'jose';
export declare type HashAlg = 'SHA-256' | 'SHA-384' | 'SHA-512';
export declare type SigningAlg = 'ES256' | 'ES384' | 'ES512';
export declare type EncryptionAlg = 'A128GCM' | 'A256GCM';
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
    [key: string]: string | number | undefined;
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
    blockCommitment?: string;
    secretCommitment?: string;
}
export interface JwkPair {
    publicJwk: JWK;
    privateJwk: JWK;
}
export interface ProofInputPayload {
    [key: string]: string | number | DataExchange | undefined;
    exchange: DataExchange;
    iat?: number;
    iss?: 'orig' | 'dest';
    proofType: string;
    poo?: string;
    por?: string;
    secret?: string;
    verificationCode?: string;
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
interface ConflictResolutionRequest {
    [key: string]: string | number;
    iss: 'orig' | 'dest';
    iat: number;
    por: string;
}
export interface VerificationRequestPayload extends ConflictResolutionRequest {
    type: 'verificationRequest';
}
export interface DisputeRequestPayload extends ConflictResolutionRequest {
    type: 'disputeRequest';
    iss: 'dest';
    cipherblock: string;
}
//# sourceMappingURL=types.d.ts.map