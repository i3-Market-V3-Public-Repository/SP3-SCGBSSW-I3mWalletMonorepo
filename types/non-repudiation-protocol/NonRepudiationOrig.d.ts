import { DataExchange, DataExchangeAgreement, JWK, JwkPair, OrigBlock, PoOPayload, PoPPayload, PoRPayload, StoredProof, TimestampVerifyOptions } from '../types';
import { NrpDltAgentOrig } from '../dlt/agents';
export declare class NonRepudiationOrig {
    agreement: DataExchangeAgreement;
    exchange: DataExchange;
    jwkPairOrig: JwkPair;
    publicJwkDest: JWK;
    block: OrigBlock;
    dltAgent: NrpDltAgentOrig;
    readonly initialized: Promise<boolean>;
    constructor(agreement: DataExchangeAgreement, privateJwk: JWK, block: Uint8Array, dltAgent: NrpDltAgentOrig);
    private init;
    private _dltSetup;
    generatePoO(): Promise<StoredProof<PoOPayload>>;
    verifyPoR(por: string, options?: Pick<TimestampVerifyOptions, 'timestamp' | 'tolerance'>): Promise<StoredProof<PoRPayload>>;
    generatePoP(): Promise<StoredProof<PoPPayload>>;
    generateVerificationRequest(): Promise<string>;
}
//# sourceMappingURL=NonRepudiationOrig.d.ts.map