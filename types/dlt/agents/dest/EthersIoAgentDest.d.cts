import { EthersIoAgent } from '../EthersIoAgent.js';
import { NrpDltAgentDest } from './NrpDltAgentDest.js';
export declare class EthersIoAgentDest extends EthersIoAgent implements NrpDltAgentDest {
    getSecretFromLedger(secretLength: number, signerAddress: string, exchangeId: string, timeout: number): Promise<{
        hex: string;
        iat: number;
    }>;
}
//# sourceMappingURL=EthersIoAgentDest.d.ts.map