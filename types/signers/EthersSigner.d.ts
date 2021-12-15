import { Provider, TransactionRequest } from '@ethersproject/abstract-provider';
import { Wallet } from '@ethersproject/wallet';
import { DltSigner } from './Signer';
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
    signTransaction(transaction: TransactionRequest): Promise<string>;
}
//# sourceMappingURL=EthersSigner.d.ts.map