import * as b64 from '@juanelas/base64'
import { bufToHex, hexToBuf } from 'bigint-conversion'
import { randBytesSync } from 'bigint-crypto-utils'
import { ethers, Wallet } from 'ethers'
import { SigningKey } from 'ethers/lib/utils'
import { EthersWalletAgent } from '../EthersWalletAgent'
import { DltConfig } from '../../../types'
import { parseHex } from '../../../utils'
import { WalletAgentOrig } from './WalletAgentOrig'

/**
 * A ledger signer using an ethers.io Wallet.
 */
export class EthersWalletAgentOrig extends EthersWalletAgent implements WalletAgentOrig {
  signer: ethers.Wallet

  constructor (privateKey?: string | Uint8Array, dltConfig?: Partial<DltConfig>) {
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
   * @returns a receipt of the deployment. In Ethereum-like DLTs it is the transaction hash, which can be used to track the transaction on the ledger
   */
  async deploySecret (secretHex: string, exchangeId: string): Promise<string> {
    const secret = ethers.BigNumber.from(parseHex(secretHex, true))
    const exchangeIdHex = parseHex(bufToHex(b64.decode(exchangeId) as Uint8Array), true)

    const unsignedTx = await this.contract.populateTransaction.setRegistry(exchangeIdHex, secret, { gasLimit: this.dltConfig.gasLimit })
    unsignedTx.nonce = await this.signer.provider.getTransactionCount(await this.getAddress())
    unsignedTx.gasPrice = await this.signer.provider.getGasPrice()
    unsignedTx.chainId = (await this.signer.provider.getNetwork()).chainId

    const signedTx = await this.signer.signTransaction(unsignedTx)

    const setRegistryTx = await this.signer.provider.sendTransaction(signedTx)

    // TO-DO: it fails with a random account since it hasn't got any funds (ethers). Do we have a faucet? Set gas prize to 0?
    // const setRegistryTx = await this.dltContract.setRegistry(`0x${this.exchange.id}`, secret, { gasLimit: this.dltConfig.gasLimit })
    return setRegistryTx.hash
  }

  async getAddress (): Promise<string> {
    return this.signer.address
  }
}
