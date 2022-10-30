import { ethers } from 'ethers';
import { DltConfig } from '../../../types';
import { EthersIoAgent } from '../EthersIoAgent';
import { NrpDltAgentOrig } from './NrpDltAgentOrig';
export declare class EthersIoAgentOrig extends EthersIoAgent implements NrpDltAgentOrig {
    signer: ethers.Wallet;
    count: number;
    constructor(dltConfig: Partial<DltConfig> & Pick<DltConfig, 'rpcProviderUrl'>, privateKey?: string | Uint8Array);
    deploySecret(secretHex: string, exchangeId: string): Promise<string>;
    getAddress(): Promise<string>;
    nextNonce(): Promise<number>;
}
//# sourceMappingURL=EthersIoAgentOrig.d.ts.map