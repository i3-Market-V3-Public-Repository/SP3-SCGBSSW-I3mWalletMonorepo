import { ethers } from 'ethers';
import { DltConfig } from '../../types';
import { NrpDltAgent } from './NrpDltAgent';
/**
 * A NRP DLT agent using the well known ethers.io library and, if required, wallet (for publishing secrets)
 */
export declare class EthersIoAgent extends NrpDltAgent {
    dltConfig: DltConfig;
    contract: ethers.Contract;
    provider: ethers.providers.Provider;
    constructor(dltConfig: Partial<DltConfig> & Pick<DltConfig, 'rpcProviderUrl'>);
    getContractAddress(): Promise<string>;
}
//# sourceMappingURL=EthersIoAgent.d.ts.map