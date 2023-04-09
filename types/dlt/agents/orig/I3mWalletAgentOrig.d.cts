import { I3mWalletAgent } from '../I3mWalletAgent.js';
import { NrpDltAgentOrig } from './NrpDltAgentOrig.js';
export declare class I3mWalletAgentOrig extends I3mWalletAgent implements NrpDltAgentOrig {
    count: number;
    deploySecret(secretHex: string, exchangeId: string): Promise<string>;
    getAddress(): Promise<string>;
    nextNonce(): Promise<number>;
}
//# sourceMappingURL=I3mWalletAgentOrig.d.ts.map