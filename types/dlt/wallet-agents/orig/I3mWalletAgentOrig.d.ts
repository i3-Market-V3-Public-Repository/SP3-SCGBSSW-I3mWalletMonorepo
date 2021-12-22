import { I3mWalletAgent } from '../I3mWalletAgent';
import { WalletAgentOrig } from './WalletAgentOrig';
export declare class I3mWalletAgentOrig extends I3mWalletAgent implements WalletAgentOrig {
    deploySecret(secretHex: string, exchangeId: string): Promise<string>;
    getAddress(): Promise<string>;
}
//# sourceMappingURL=I3mWalletAgentOrig.d.ts.map