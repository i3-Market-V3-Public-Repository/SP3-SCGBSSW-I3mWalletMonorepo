import { HttpInitiatorTransport, Session } from '@i3m/wallet-protocol';
import { EthersWalletAgent } from './EthersWalletAgent';
import { DltConfig } from '../../types';
export declare class I3mWalletAgent extends EthersWalletAgent {
    session: Session<HttpInitiatorTransport>;
    did: string;
    constructor(session: Session<HttpInitiatorTransport>, did: string, dltConfig?: Partial<DltConfig>);
}
//# sourceMappingURL=I3mWalletAgent.d.ts.map