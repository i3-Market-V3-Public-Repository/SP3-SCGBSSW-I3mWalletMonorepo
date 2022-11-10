import { EthersIoAgent } from '../EthersIoAgent';
import { NrpDltAgentDest } from './NrpDltAgentDest';
export declare class EthersIoAgentDest extends EthersIoAgent implements NrpDltAgentDest {
    getSecretFromLedger(secretLength: number, signerAddress: string, exchangeId: string, timeout: number): Promise<{
        hex: string;
        iat: number;
    }>;
}
//# sourceMappingURL=EthersIoAgentDest.d.ts.map