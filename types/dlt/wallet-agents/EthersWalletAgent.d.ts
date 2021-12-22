import { ethers } from 'ethers';
import { DltConfig } from '../../types';
import { WalletAgent } from './WalletAgent';
/**
 * A ledger signer using an ethers.io Wallet.
 */
export declare class EthersWalletAgent extends WalletAgent {
    dltConfig: DltConfig;
    contract: ethers.Contract;
    provider: ethers.providers.Provider;
    constructor(dltConfig?: Partial<DltConfig>);
    getContractAddress(): Promise<string>;
}
//# sourceMappingURL=EthersWalletAgent.d.ts.map