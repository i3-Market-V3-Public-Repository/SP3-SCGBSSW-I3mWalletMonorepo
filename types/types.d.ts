import { JWK, JWTPayload } from 'jose';
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
    dataExchange: DataExchangeInit;
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