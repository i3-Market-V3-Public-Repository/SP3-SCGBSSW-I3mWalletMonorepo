
/**
 * An abstract class that should be implemeneted by any agent providing connection to the smart contract of the non-repudiation protocol.
 */
export abstract class NrpDltAgent {
  /**
   * Returns the address of the smart contract in use
   */
  abstract getContractAddress (): Promise<string>
}
