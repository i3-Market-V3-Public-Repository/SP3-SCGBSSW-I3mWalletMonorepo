
/**
 * An abstract class that should be implemeneted by any signer for the ledger.
 * A SW-based ethers.io Walllet is provided (EthersSigner) as a reference implementation
 */
export abstract class WalletAgent {
  /**
   * Returns the address of the smart contract in use
   */
  abstract getContractAddress (): Promise<string>
}
