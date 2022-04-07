import { WalletAgent } from '../WalletAgent';
export interface WalletAgentOrig extends WalletAgent {
    /**
     * Publish the secret for a given data exchange on the ledger.
     *
     * @param secretHex - the secret in hexadecimal
     * @param exchangeId - the exchange id
     *
     * @returns a receipt of the deployment. In Ethereum-like DLTs it contains the transaction hash, which can be used to track the transaction on the ledger
     */
    deploySecret: (secretHex: string, exchangeId: string) => Promise<string>;
    /**
     * Returns and identifier of the signer's account on the ledger. In Ethereum-like DLTs is the Ethereum address
     */
    getAddress: () => Promise<string>;
}
//# sourceMappingURL=WalletAgentOrig.d.ts.map