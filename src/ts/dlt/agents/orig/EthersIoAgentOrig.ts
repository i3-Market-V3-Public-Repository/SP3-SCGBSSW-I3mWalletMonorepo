import { hexToBuf } from 'bigint-conversion'
import { randBytesSync } from 'bigint-crypto-utils'
import { ethers, Wallet } from 'ethers'
import { SigningKey } from 'ethers/lib/utils'
import { DltConfig } from '../../../types'
import { secretUnisgnedTransaction } from '../secret'
import { EthersIoAgent } from '../EthersIoAgent'
import { NrpDltAgentOrig } from './NrpDltAgentOrig'

/**
 * A DLT agent for the NRP orig using ethers.io.
 */
export class EthersIoAgentOrig extends EthersIoAgent implements NrpDltAgentOrig {
  signer: ethers.Wallet

  /**
  * The nonce of the next transaction to send to the blockchain. It keep track also of tx sent to the DLT bu not yet published on the blockchain
  */
  count: number = -1

  constructor (dltConfig: Partial<DltConfig> & Pick<DltConfig, 'rpcProviderUrl'>, privateKey?: string | Uint8Array) {
    super(dltConfig)

    let privKey: Uint8Array
    if (privateKey === undefined) {
      privKey = randBytesSync(32)
    } else {
      privKey = (typeof privateKey === 'string') ? new Uint8Array(hexToBuf(privateKey)) : privateKey
    }
    const signingKey = new SigningKey(privKey)

    this.signer = new Wallet(signingKey, this.provider)
  }

  /**
   * Publish the secret for a given data exchange on the ledger.
   *
   * @param secretHex - the secret in hexadecimal
   * @param exchangeId - the exchange id
   *
   * @returns a receipt of the deployment. In Ethereum-like DLTs it contains the transaction hash, which can be used to track the transaction on the ledger, and the nonce of the transaction
   */
  async deploySecret (secretHex: string, exchangeId: string): Promise<string> {
    const unsignedTx = await secretUnisgnedTransaction(secretHex, exchangeId, this) as any

    const signedTx = await this.signer.signTransaction(unsignedTx)

    const setRegistryTx = await this.signer.provider.sendTransaction(signedTx)

    this.count = this.count + 1

    // TO-DO: it fails with a random account since it hasn't got any funds (ethers). Do we have a faucet? Set gas prize to 0?

    return setRegistryTx.hash
  }

  async getAddress (): Promise<string> {
    return this.signer.address
  }

  async nextNonce (): Promise<number> {
    const publishedCount = await this.provider.getTransactionCount(await this.getAddress(), 'pending') // Nonce of the next transaction to be published (including nonces in pending state)
    if (publishedCount > this.count) {
      this.count = publishedCount
    }
    return this.count
  }
}
