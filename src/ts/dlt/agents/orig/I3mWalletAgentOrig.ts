import { NrError } from '../../../errors'
import { secretUnisgnedTransaction } from '../secret'
import { I3mWalletAgent } from '../I3mWalletAgent'
import { NrpDltAgentOrig } from './NrpDltAgentOrig'

/**
 * A DLT agent for the NRP orig using ethers.io library and the i3m-wallet for signing transactions to the DLT
 */
export class I3mWalletAgentOrig extends I3mWalletAgent implements NrpDltAgentOrig {
  /**
  * The nonce of the next transaction to send to the blockchain. It keep track also of tx sent to the DLT bu not yet published on the blockchain
  */
  count: number = -1

  async deploySecret (secretHex: string, exchangeId: string): Promise<string> {
    await this.initialized

    const unsignedTx = await secretUnisgnedTransaction(secretHex, exchangeId, this)

    const response = await this.wallet.identities.sign({ did: this.did }, {
      type: 'Transaction',
      data: unsignedTx
    })

    const signedTx = response.signature

    const setRegistryTx = await this.provider.sendTransaction(signedTx)

    this.count = this.count + 1

    // TO-DO: it fails with a random account since it hasn't got any funds (ethers). Do we have a faucet? Set gas prize to 0?
    // const setRegistryTx = await this.dltContract.setRegistry(`0x${this.exchange.id}`, secret, { gasLimit: this.dltConfig.gasLimit })
    return setRegistryTx.hash
  }

  async getAddress (): Promise<string> {
    await this.initialized

    const json = await this.wallet.identities.info({ did: this.did })
    if (json.addresses === undefined) {
      throw new NrError(new Error('no addresses for did ' + this.did), ['unexpected error'])
    }
    return json.addresses[0] // TODO: in the future there could be more than one address per DID
  }

  async nextNonce (): Promise<number> {
    await this.initialized

    const publishedCount = await this.provider.getTransactionCount(await this.getAddress(), 'pending') // Nonce of the next transaction to be published (including nonces in pending state)
    if (publishedCount > this.count) {
      this.count = publishedCount
    }
    return this.count
  }
}
