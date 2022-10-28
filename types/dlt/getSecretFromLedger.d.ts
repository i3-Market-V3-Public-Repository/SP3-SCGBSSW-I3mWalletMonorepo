import { ethers } from 'ethers';
export declare function getSecretFromLedger(contract: ethers.Contract, signerAddress: string, exchangeId: string, timeout: number): Promise<{
    hex: string;
    iat: number;
}>;
//# sourceMappingURL=getSecretFromLedger.d.ts.map