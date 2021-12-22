import { Provider, TransactionRequest } from '@ethersproject/abstract-provider'
import { SigningKey } from '@ethersproject/signing-key'
import { Wallet } from '@ethersproject/wallet'
import { hexToBuf } from 'bigint-conversion'
import { DltSigner } from './DltSigner'

/**
 * A ledger signer using an ethers.io Wallet.
 */
export class EthersSigner implements DltSigner {
  signer: Wallet

  /**
   *
   * @param provider
   * @param privateKey the private key as an hexadecimal string ot Uint8Array
   */
  constructor (provider: Provider, privateKey: string | Uint8Array) {
    const privKey = (typeof privateKey === 'string') ? new Uint8Array(hexToBuf(privateKey)) : privateKey
    const signingKey = new SigningKey(privKey)
    this.signer = new Wallet(signingKey, provider)
  }

  /**
   * This function gets an unsigned transaction, signs it with private, and deploys it to the ledger
   *
   * @param unsignedTx - an unsigned transactions. From, nonce, gaslimit will be filled by the Signer
   *
   * @returns a receipt of the deployment. In Ethereum-like DLTs it is the transaction hash, which can be used to track the transaction on the ledger
   */
  async deployTransaction (unsignedTx: TransactionRequest): Promise<string> {
    unsignedTx.nonce = await this.signer.provider.getTransactionCount(await this.getId())
    unsignedTx.gasPrice = await this.signer.provider.getGasPrice()
    unsignedTx.chainId = (await this.signer.provider.getNetwork()).chainId

    const signedTx = await this.signer.signTransaction(unsignedTx)

    const setRegistryTx = await this.signer.provider.sendTransaction(signedTx)

    // TO-DO: it fails with a random account since it hasn't got any funds (ethers). Do we have a faucet? Set gas prize to 0?
    // const setRegistryTx = await this.dltContract.setRegistry(`0x${this.exchange.id}`, secret, { gasLimit: this.dltConfig.gasLimit })
    return setRegistryTx.hash
  }

  async getId (): Promise<string> {
    return await this.signer.getAddress()
  }
}
