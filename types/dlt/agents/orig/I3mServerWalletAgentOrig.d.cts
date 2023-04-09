import { I3mServerWalletAgent } from '../I3mServerWalletAgent.js';
import { NrpDltAgentOrig } from './NrpDltAgentOrig.js';
export declare class I3mServerWalletAgentOrig extends I3mServerWalletAgent implements NrpDltAgentOrig {
    count: number;
    deploySecret(secretHex: string, exchangeId: string): Promise<string>;
    getAddress(): Promise<string>;
    nextNonce(): Promise<number>;
}
//# sourceMappingURL=I3mServerWalletAgentOrig.d.ts.map