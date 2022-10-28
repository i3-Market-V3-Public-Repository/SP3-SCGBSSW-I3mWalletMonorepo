import { I3mWalletAgent } from '../I3mWalletAgent';
import { NrpDltAgentDest } from './NrpDltAgentDest';
export declare class I3mWalletAgentDest extends I3mWalletAgent implements NrpDltAgentDest {
    getSecretFromLedger(signerAddress: string, exchangeId: string, timeout: number): Promise<{
        hex: string;
        iat: number;
    }>;
}
//# sourceMappingURL=I3mWalletAgentDest.d.ts.map