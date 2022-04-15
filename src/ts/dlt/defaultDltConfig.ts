import { ContractConfig, DltConfig } from '../types'
import contractConfig from '@i3m/non-repudiation-protocol-smart-contract'

export const defaultDltConfig: Omit<DltConfig, 'rpcProviderUrl'> = {
  gasLimit: 12500000,
  contract: contractConfig as ContractConfig
}
