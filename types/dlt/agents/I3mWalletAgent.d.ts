import { EthersIoAgent } from './EthersIoAgent';
import { DltConfig } from '../../types';
import { WalletApi } from '@i3m/wallet-protocol-api/types';
export declare class I3mWalletAgent extends EthersIoAgent {
    wallet: WalletApi;
    did: string;
    constructor(wallet: WalletApi, did: string, dltConfig?: Partial<Omit<DltConfig, 'rpcProviderUrk'>>);
}
//# sourceMappingURL=I3mWalletAgent.d.ts.map