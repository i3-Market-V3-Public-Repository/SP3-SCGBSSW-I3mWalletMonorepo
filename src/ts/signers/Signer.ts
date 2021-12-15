
/**
 * An abstract class that should be implemeneted by any signer for the ledger.
 * A SW-based ethers.io Walllet is provided (EthersSigner) as a reference implementation
 */
export abstract class DltSigner {
  async signTransaction (transaction: {}): Promise<string> {
    throw new Error('not implemented')
  }
}
