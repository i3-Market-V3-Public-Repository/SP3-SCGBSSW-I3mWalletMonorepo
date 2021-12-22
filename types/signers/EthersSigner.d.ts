import { Provider, TransactionRequest } from '@ethersproject/abstract-provider';
import { Wallet } from '@ethersproject/wallet';
import { DltSigner } from './DltSigner';
/**
 * A ledger signer using an ethers.io Wallet.
 */
export declare class EthersSigner implements DltSigner {
    signer: Wallet;
    /**
     *
     * @param provider
     * @param privateKey the private key as an hexadecimal string ot Uint8Array
     */
    constructor(provider: Provider, privateKey: string | Uint8Array);
    /**
     * This function gets an unsigned transaction, signs it with private, and deploys it to the ledger
     *
     * @param unsignedTx - an unsigned transactions. From, nonce, gaslimit will be filled by the Signer
     *
     * @returns a receipt of the deployment. In Ethereum-like DLTs it is the transaction hash, which can be used to track the transaction on the ledger
     */
    deployTransaction(unsignedTx: TransactionRequest): Promise<string>;
    getId(): Promise<string>;
}
//# sourceMappingURL=EthersSigner.d.ts.map