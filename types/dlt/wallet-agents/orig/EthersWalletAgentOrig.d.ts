import { ethers } from 'ethers';
import { EthersWalletAgent } from '../EthersWalletAgent';
import { DltConfig } from '../../../types';
import { WalletAgentOrig } from './WalletAgentOrig';
/**
 * A ledger signer using an ethers.io Wallet.
 */
export declare class EthersWalletAgentOrig extends EthersWalletAgent implements WalletAgentOrig {
    signer: ethers.Wallet;
    /**
    * The nonce of the next transaction to send to the blockchain. It keep track also of tx sent to the DLT bu not yet published on the blockchain
    */
    count: number;
    constructor(privateKey?: string | Uint8Array, dltConfig?: Partial<DltConfig>);
    /**
     * Publish the secret for a given data exchange on the ledger.
     *
     * @param secretHex - the secret in hexadecimal
     * @param exchangeId - the exchange id
     *
     * @returns a receipt of the deployment. In Ethereum-like DLTs it contains the transaction hash, which can be used to track the transaction on the ledger, and the nonce of the transaction
     */
    deploySecret(secretHex: string, exchangeId: string): Promise<string>;
    getAddress(): Promise<string>;
    nextNonce(): Promise<number>;
}
//# sourceMappingURL=EthersWalletAgentOrig.d.ts.map