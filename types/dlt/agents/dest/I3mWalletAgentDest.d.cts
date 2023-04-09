import { I3mWalletAgent } from '../I3mWalletAgent.js';
import { NrpDltAgentDest } from './NrpDltAgentDest.js';
export declare class I3mWalletAgentDest extends I3mWalletAgent implements NrpDltAgentDest {
    getSecretFromLedger(secretLength: number, signerAddress: string, exchangeId: string, timeout: number): Promise<{
        hex: string;
        iat: number;
    }>;
}
//# sourceMappingURL=I3mWalletAgentDest.d.ts.map