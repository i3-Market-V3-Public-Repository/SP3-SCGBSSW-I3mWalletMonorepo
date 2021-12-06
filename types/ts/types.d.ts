import { ContractInterface } from '@ethersproject/contracts';
import { JWK, JWTPayload } from 'jose';
import { Contract, Wallet } from 'ethers';
export declare type HashAlg = 'SHA-256' | 'SHA-384' | 'SHA-512';
export declare type SigningAlg = 'ES256' | 'ES384' | 'ES512';
export declare type EncryptionAlg = 'A128GCM' | 'A256GCM';
export interface Algs {
    hashAlg?: HashAlg;
    SigningAlg?: SigningAlg;
    EncAlg?: EncryptionAlg;
}
export interface ContractConfig {
    address: string;
    abi: ContractInterface;
}
export interface Signer {
    address: string;
    signer?: Wallet;
}
export interface DltConfig {
    rpcProviderUrl: string;
    gasLimit: number;
    contractConfig: ContractConfig;
    contract: Contract;
    signer?: Signer;
    disable: boolean;
}
export interface Block {
    raw?: Uint8Array;
    jwe?: string;
    secret?: {
        jwk: JWK;
        hex: string;
    };
    poo?: string;
    por?: string;
    pop?: string;
}
export interface OrigBlock extends Block {
    raw: Uint8Array;
    jwe: string;
    secret: {
        jwk: JWK;
        hex: string;
    };
}
export interface DateTolerance {
    clockTolerance: string | number;
    currentDate: Date;
}
export interface DataExchangeInit {
    id: string;
    orig: string;
    dest: string;
    hashAlg: HashAlg;
    encAlg: EncryptionAlg;
    signingAlg: SigningAlg;
    ledgerContract: string;
    ledgerSignerAddress: string;
    cipherblockDgst?: string;
    blockCommitment?: string;
    secretCommitment?: string;
    schema?: string;
}
export interface DataExchange extends DataExchangeInit {
    cipherblockDgst: string;
    blockCommitment: string;
    secretCommitment: string;
}
export interface JwkPair {
    publicJwk: JWK;
    privateJwk: JWK;
}
interface ProofCommonPayload extends JWTPayload {
    exchange: DataExchangeInit;
}
export interface PoOPayload extends ProofCommonPayload {
    iss: 'orig';
    proofType: 'PoO';
}
export interface PoRPayload extends ProofCommonPayload {
    iss: 'dest';
    proofType: 'PoR';
    poo: string;
}
export interface PoPPayload extends ProofCommonPayload {
    iss: 'orig';
    proofType: 'PoP';
    por: string;
    secret: string;
    verificationCode: string;
}
export declare type ProofInputPayload = PoOPayload | PoRPayload | PoPPayload;
export declare type ProofPayload = ProofInputPayload & {
    iat: number;
};
export {};
//# sourceMappingURL=types.d.ts.map