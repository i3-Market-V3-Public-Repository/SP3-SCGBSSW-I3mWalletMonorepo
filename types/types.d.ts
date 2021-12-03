import { JWK, JWTPayload } from 'jose';
export interface Block {
    raw?: Uint8Array;
    jwe?: string;
    secret?: JWK;
    poo?: string;
    por?: string;
    pop?: string;
}
export interface DestBlock extends Block {
    jwe: string;
}
export interface OrigBlock extends Block {
    raw: Uint8Array;
}
export interface DateTolerance {
    clockTolerance: string | number;
    currentDate: Date;
}
export interface DataExchange {
    id: string;
    orig: string;
    dest: string;
    hashAlg: string;
    cipherblockDgst: string;
    blockCommitment: string;
    secretCommitment: string;
    schema?: string;
}
export interface DataExchangeInit {
    id: string;
    orig: string;
    dest: string;
    hashAlg: string;
    cipherblockDgst?: string;
    blockCommitment?: string;
    secretCommitment?: string;
    schema?: string;
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
    pooDgst: string;
}
export interface PoPPayload extends ProofCommonPayload {
    iss: 'orig';
    proofType: 'PoP';
    porDgst: string;
    secret: string;
    verificationCode: string;
}
export declare type ProofInputPayload = PoOPayload | PoRPayload | PoPPayload;
export declare type ProofPayload = ProofInputPayload & {
    iat: number;
};
export {};
//# sourceMappingURL=types.d.ts.map