import { I3mWalletAgent } from '../I3mWalletAgent';
import { NrpDltAgentOrig } from './NrpDltAgentOrig';
export declare class I3mWalletAgentOrig extends I3mWalletAgent implements NrpDltAgentOrig {
    count: number;
    deploySecret(secretHex: string, exchangeId: string): Promise<string>;
    getAddress(): Promise<string>;
    nextNonce(): Promise<number>;
}
//# sourceMappingURL=I3mWalletAgentOrig.d.ts.map