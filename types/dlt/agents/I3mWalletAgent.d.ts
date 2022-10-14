import { HttpInitiatorTransport, Session } from '@i3m/wallet-protocol';
import { EthersIoAgent } from './EthersIoAgent';
import { DltConfig } from '../../types';
export declare class I3mWalletAgent extends EthersIoAgent {
    session: Session<HttpInitiatorTransport>;
    did: string;
    constructor(session: Session<HttpInitiatorTransport>, did: string, dltConfig: Partial<DltConfig> & Pick<DltConfig, 'rpcProviderUrl'>);
}
//# sourceMappingURL=I3mWalletAgent.d.ts.map