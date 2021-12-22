import { ethers } from 'ethers';
import { EthersWalletAgent } from '../EthersWalletAgent';
import { DltConfig } from '../../../types';
import { WalletAgentOrig } from './WalletAgentOrig';
/**
 * A ledger signer using an ethers.io Wallet.
 */
export declare class EthersWalletAgentOrig extends EthersWalletAgent implements WalletAgentOrig {
    signer: ethers.Wallet;
    constructor(privateKey?: string | Uint8Array, dltConfig?: Partial<DltConfig>);
    /**
     * Publish the secret for a given data exchange on the ledger.
     *
     * @param secretHex - the secret in hexadecimal
     * @param exchangeId - the exchange id
     *
     * @returns a receipt of the deployment. In Ethereum-like DLTs it is the transaction hash, which can be used to track the transaction on the ledger
     */
    deploySecret(secretHex: string, exchangeId: string): Promise<string>;
    getAddress(): Promise<string>;
}
//# sourceMappingURL=EthersWalletAgentOrig.d.ts.map