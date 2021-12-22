import * as b64 from '@juanelas/base64'
import { bufToHex } from 'bigint-conversion'
import { ethers } from 'ethers'
import { I3mWalletAgent } from '../I3mWalletAgent'
import { parseHex } from '../../../utils'
import { WalletAgentOrig } from './WalletAgentOrig'

export class I3mWalletAgentOrig extends I3mWalletAgent implements WalletAgentOrig {
  async deploySecret (secretHex: string, exchangeId: string): Promise<string> {
    const secret = ethers.BigNumber.from(parseHex(secretHex, true))
    const exchangeIdHex = parseHex(bufToHex(b64.decode(exchangeId) as Uint8Array), true)

    const unsignedTx = await this.contract.populateTransaction.setRegistry(exchangeIdHex, secret, { gasLimit: this.dltConfig.gasLimit }) as any
    unsignedTx.nonce = await this.provider.getTransactionCount(await this.getAddress())

    unsignedTx.gasLimit = unsignedTx.gasLimit?._hex
    unsignedTx.gasPrice = (await this.provider.getGasPrice())._hex
    unsignedTx.chainId = (await this.provider.getNetwork()).chainId
    const address = await this.getAddress()
    unsignedTx.from = parseHex(address, true)
    const response = await this.session.send({
      url: `/identities/${this.did}/sign`,
      init: {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          type: 'Transaction',
          data: unsignedTx
        })
      }
    })
    if (response.status !== 200) {
      throw new Error(response.body)
    }
    const json = JSON.parse(response.body)
    const signedTx = json.signature

    const setRegistryTx = await this.provider.sendTransaction(signedTx)

    // TO-DO: it fails with a random account since it hasn't got any funds (ethers). Do we have a faucet? Set gas prize to 0?
    // const setRegistryTx = await this.dltContract.setRegistry(`0x${this.exchange.id}`, secret, { gasLimit: this.dltConfig.gasLimit })
    return setRegistryTx.hash
  }

  async getAddress (): Promise<string> {
    const response = await this.session.send({
      url: `/identities/${this.did}/info`,
      init: {
        method: 'GET'
      }
    })
    const json = JSON.parse(response.body)
    return json.addresses[0] // TODO: in the future there could be more than one address per DID
  }
}
