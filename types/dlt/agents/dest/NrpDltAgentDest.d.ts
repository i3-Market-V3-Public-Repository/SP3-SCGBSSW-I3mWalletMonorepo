import { NrpDltAgent } from '../NrpDltAgent';
export interface NrpDltAgentDest extends NrpDltAgent {
    getSecretFromLedger: (secretLength: number, signerAddress: string, exchangeId: string, timeout: number) => Promise<{
        hex: string;
        iat: number;
    }>;
}
//# sourceMappingURL=NrpDltAgentDest.d.ts.map