
import { SharedMemory } from '@wallet/lib'
import { SettingsMetadata, SettingsValueOrFunction } from './settings-metadata'

export function executeFunctionOrValue<V, T> (valueOrFunction: SettingsValueOrFunction<V, T>, metadata: SettingsMetadata, value: T, sh: SharedMemory): V {
  if (valueOrFunction instanceof Function) {
    return valueOrFunction(metadata.key, value, metadata, sh)
  }
  return valueOrFunction
}
