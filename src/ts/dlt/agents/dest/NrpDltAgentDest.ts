import { NrpDltAgent } from '../NrpDltAgent'

export interface NrpDltAgentDest extends NrpDltAgent{
  /**
   * Just in case the PoP is not received, the secret can be downloaded from the ledger.
   * The secret should be downloaded before poo.iat + pooToPop max delay.
   * @param secretLength - the expected length of the secret to get
   * @param signerAddress - the address (hexadecimal) of the entity publishing the secret.
   * @param exchangeId - the id of the data exchange
   * @param timeout - the timeout in seconds for waiting for the secret to be published on the ledger
   * @returns the secret in hex and when it was published to the blockchain as a NumericDate
   */
  getSecretFromLedger: (secretLength: number, signerAddress: string, exchangeId: string, timeout: number) => Promise<{hex: string, iat: number}>
}
