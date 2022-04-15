import { I3mWalletAgent } from '../I3mWalletAgent';
import { NrpDltAgentOrig } from './NrpDltAgentOrig';
/**
 * A DLT agent for the NRP orig using ethers.io library and the i3m-wallet for signing transactions to the DLT
 */
export declare class I3mWalletAgentOrig extends I3mWalletAgent implements NrpDltAgentOrig {
    /**
    * The nonce of the next transaction to send to the blockchain. It keep track also of tx sent to the DLT bu not yet published on the blockchain
    */
    count: number;
    deploySecret(secretHex: string, exchangeId: string): Promise<string>;
    getAddress(): Promise<string>;
    nextNonce(): Promise<number>;
}
//# sourceMappingURL=I3mWalletAgentOrig.d.ts.map