/**
 * An abstract class that should be implemeneted by any signer for the ledger.
 * A SW-based ethers.io Walllet is provided (EthersSigner) as a reference implementation
 */
export declare abstract class WalletAgent {
    /**
     * Returns the address of the smart contract in use
     */
    abstract getContractAddress(): Promise<string>;
}
//# sourceMappingURL=WalletAgent.d.ts.map