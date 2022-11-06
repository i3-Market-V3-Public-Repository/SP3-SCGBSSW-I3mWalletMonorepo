import { Identity } from '../internal';
export interface PublicKeyExchangeRequest {
    method: 'publicKeyExchange';
    sender: Identity;
    publicKey: string;
    ra?: string;
}
export interface CommitmentRequest {
    method: 'commitment';
    cx: string;
}
export interface NonceRevealRequest {
    method: 'nonce';
    nx: string;
}
export interface VerificationRequest {
    method: 'verification';
}
export interface VerificationChallengeRequest {
    method: 'verificationChallenge';
    ciphertext: string;
}
export interface AcknowledgementRequest {
    method: 'acknowledgement';
}
export declare type Request = PublicKeyExchangeRequest | CommitmentRequest | NonceRevealRequest | VerificationRequest | VerificationChallengeRequest | AcknowledgementRequest;
//# sourceMappingURL=request.d.ts.map