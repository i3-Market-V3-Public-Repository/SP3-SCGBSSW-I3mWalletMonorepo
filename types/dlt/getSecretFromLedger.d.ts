import { ethers } from 'ethers';
/**
 * Just in case the PoP is not received, the secret can be downloaded from the ledger.
 * The secret should be downloaded before poo.iat + pooToPop max delay.
 * @param contract - an Ethers Contract
 * @param signerAddress - the address (hexadecimal) of the entity publishing the secret.
 * @param exchangeId - the id of the data exchange
 * @param timeout - the timeout in seconds for waiting for the secret to be published on the ledger
 * @returns
 */
export declare function getSecretFromLedger(contract: ethers.Contract, signerAddress: string, exchangeId: string, timeout?: number): Promise<{
    hex: string;
    iat: number;
}>;
//# sourceMappingURL=getSecretFromLedger.d.ts.map