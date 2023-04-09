import { ethers } from 'ethers';
import { DltConfig } from '../../types.js';
import { NrpDltAgent } from './NrpDltAgent.js';
export declare class EthersIoAgent extends NrpDltAgent {
    dltConfig: DltConfig;
    contract: ethers.Contract;
    provider: ethers.providers.Provider;
    initialized: Promise<boolean>;
    constructor(dltConfig: (Partial<DltConfig> & Pick<DltConfig, 'rpcProviderUrl'>) | Promise<(Partial<DltConfig> & Pick<DltConfig, 'rpcProviderUrl'>)>);
    getContractAddress(): Promise<string>;
}
//# sourceMappingURL=EthersIoAgent.d.ts.map