import { ethers } from 'ethers'
import { NrError } from '../errors'
import { parseHex } from '../utils/'
import * as b64 from '@juanelas/base64'
import { bufToHex } from 'bigint-conversion'

/**
 * Just in case the PoP is not received, the secret can be downloaded from the ledger.
 * The secret should be downloaded before poo.iat + pooToPop max delay.
 * @param contract - an Ethers Contract
 * @param signerAddress - the address (hexadecimal) of the entity publishing the secret.
 * @param exchangeId - the id of the data exchange
 * @param timeout - the timeout in seconds for waiting for the secret to be published on the ledger
 * @returns
 */
export async function getSecretFromLedger (contract: ethers.Contract, signerAddress: string, exchangeId: string, timeout: number = 0): Promise<{hex: string, iat: number}> {
  let secretBn = ethers.BigNumber.from(0)
  let timestampBn = ethers.BigNumber.from(0)
  const exchangeIdHex = parseHex(bufToHex(b64.decode(exchangeId) as ArrayBuffer), true)
  let counter = 0
  do {
    try {
      ({ secret: secretBn, timestamp: timestampBn } = await contract.registry(parseHex(signerAddress, true), exchangeIdHex))
    } catch (error) {
      throw new NrError(error, ['cannot contact the ledger'])
    }
    if (secretBn.isZero()) {
      counter++
      await new Promise(resolve => setTimeout(resolve, 1000))
    }
  } while (secretBn.isZero() && counter < timeout)
  if (secretBn.isZero()) {
    throw new NrError(new Error(`timeout of ${timeout}s exceeded when querying the ledger and secret still not published`), ['secret not published'])
  }
  const hex = parseHex(secretBn.toHexString(), false)
  const iat = timestampBn.toNumber()

  return { hex, iat }
}
