import { ethers } from 'ethers'
import { NrError } from '../errors/index.js'
import { parseHex } from './parseHex.js'
/**
 * Verifies and returns the ethereum address in EIP-55 format
 * @param a
 * @returns
 */
export function parseAddress (a: string): string {
  const hexMatch = a.match(/^(0x)?([\da-fA-F]{40})$/)
  if (hexMatch == null) {
    throw new RangeError('incorrect address format')
  }
  try {
    const hex = parseHex(a, true, 20)
    return ethers.utils.getAddress(hex)
  } catch (error) {
    throw new NrError(error, ['invalid EIP-55 address'])
  }
}
