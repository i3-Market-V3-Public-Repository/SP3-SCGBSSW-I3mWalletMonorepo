import { EthersIoAgent } from './EthersIoAgent';
import { DltConfig } from '../../types';
import { ServerWallet } from '@i3m/server-wallet/types';
export declare class I3mServerWalletAgent extends EthersIoAgent {
    wallet: ServerWallet;
    did: string;
    constructor(serverWallet: ServerWallet, did: string, dltConfig?: Partial<Omit<DltConfig, 'rpcProviderUrk'>>);
}
//# sourceMappingURL=I3mServerWalletAgent.d.ts.map