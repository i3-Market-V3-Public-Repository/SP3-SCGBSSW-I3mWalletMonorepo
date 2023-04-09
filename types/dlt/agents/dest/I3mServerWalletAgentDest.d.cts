import { I3mServerWalletAgent } from '../I3mServerWalletAgent.js';
import { NrpDltAgentDest } from './NrpDltAgentDest.js';
export declare class I3mServerWalletAgentDest extends I3mServerWalletAgent implements NrpDltAgentDest {
    getSecretFromLedger(secretLength: number, signerAddress: string, exchangeId: string, timeout: number): Promise<{
        hex: string;
        iat: number;
    }>;
}
//# sourceMappingURL=I3mServerWalletAgentDest.d.ts.map