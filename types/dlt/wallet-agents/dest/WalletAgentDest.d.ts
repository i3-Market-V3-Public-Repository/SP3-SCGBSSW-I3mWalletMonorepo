import { WalletAgent } from '../WalletAgent';
export interface WalletAgentDest extends WalletAgent {
    /**
     * Just in case the PoP is not received, the secret can be downloaded from the ledger.
     * The secret should be downloaded before poo.iat + pooToPop max delay.
     * @param signerAddress - the address (hexadecimal) of the entity publishing the secret.
     * @param exchangeId - the id of the data exchange
     * @param timeout - the timeout in seconds for waiting for the secret to be published on the ledger
     * @returns the secret in hex and when it was published to the blockchain as a NumericDate
     */
    getSecretFromLedger: (signerAddress: string, exchangeId: string, timeout: number) => Promise<{
        hex: string;
        iat: number;
    }>;
}
//# sourceMappingURL=WalletAgentDest.d.ts.map