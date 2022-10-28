import { I3mServerWalletAgent } from '../I3mServerWalletAgent';
import { NrpDltAgentDest } from './NrpDltAgentDest';
export declare class I3mServerWalletAgentDest extends I3mServerWalletAgent implements NrpDltAgentDest {
    getSecretFromLedger(signerAddress: string, exchangeId: string, timeout: number): Promise<{
        hex: string;
        iat: number;
    }>;
}
//# sourceMappingURL=I3mServerWalletAgentDest.d.ts.map