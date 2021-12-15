/**
 * An abstract class that should be implemeneted by any signer for the ledger.
 * A SW-based ethers.io Walllet is provided (EthersSigner) as a reference implementation
 */
export declare abstract class DltSigner {
    signTransaction(transaction: {}): Promise<string>;
}
//# sourceMappingURL=Signer.d.ts.map