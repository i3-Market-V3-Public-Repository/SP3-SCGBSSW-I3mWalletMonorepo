import { EthersIoAgent } from '../EthersIoAgent';
import { NrpDltAgentDest } from './NrpDltAgentDest';
/**
 * A DLT agent for the NRP dest using ethers.io.
 */
export declare class EthersIoAgentDest extends EthersIoAgent implements NrpDltAgentDest {
    getSecretFromLedger(signerAddress: string, exchangeId: string, timeout: number): Promise<{
        hex: string;
        iat: number;
    }>;
}
//# sourceMappingURL=EthersIoAgentDest.d.ts.map