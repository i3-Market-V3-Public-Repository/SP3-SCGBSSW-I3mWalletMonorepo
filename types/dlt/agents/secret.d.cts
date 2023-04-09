import { ethers } from 'ethers';
import { NrpDltAgentOrig } from './orig/index.js';
import { EthersIoAgent } from './EthersIoAgent.js';
export declare function getSecretFromLedger(contract: ethers.Contract, signerAddress: string, exchangeId: string, timeout: number, secretLength: number): Promise<{
    hex: string;
    iat: number;
}>;
export declare function secretUnisgnedTransaction(secretHex: string, exchangeId: string, agent: EthersIoAgent & NrpDltAgentOrig): Promise<ethers.UnsignedTransaction>;
//# sourceMappingURL=secret.d.ts.map