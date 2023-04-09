import { WalletApi } from '@i3m/wallet-protocol-api/types';
import { DltConfig } from '../../types.js';
import { EthersIoAgent } from './EthersIoAgent.js';
export declare class I3mWalletAgent extends EthersIoAgent {
    wallet: WalletApi;
    did: string;
    constructor(wallet: WalletApi, did: string, dltConfig?: Partial<Omit<DltConfig, 'rpcProviderUrl'>>);
}
//# sourceMappingURL=I3mWalletAgent.d.ts.map