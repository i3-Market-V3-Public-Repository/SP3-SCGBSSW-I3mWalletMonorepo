import { EncSettingsAlgorithms, BaseEncSettings, BaseAuthSettings } from '@wallet/lib'
import { EncryptionKeys, EncryptionKeysConstructor } from '../key-generators'

import { Pbkdf2EncKeys } from './pbkdf2'

const encKeysByType: Record<EncSettingsAlgorithms, EncryptionKeysConstructor> = {
  'pbkdf.2': Pbkdf2EncKeys
}

export const currentEncAlgorithm: EncSettingsAlgorithms = 'pbkdf.2'

export const loadEncKeyAlgorithm = (auth?: BaseAuthSettings, enc?: BaseEncSettings): EncryptionKeys => {
  if (enc === undefined) {
    if (auth === undefined) {
      return new (encKeysByType[currentEncAlgorithm])({})
    }

    // When there is no enc data but there is auth data means that the settings are form an older version
    // This version had Pbkdf2 for the enc keys and auth keys with the same salt
    return new Pbkdf2EncKeys(auth)
  }

  if (enc.algorithm === undefined) {
    return new Pbkdf2EncKeys(enc as any)
  }

  return new (encKeysByType[enc.algorithm])(enc)
}

export const getCurrentEncKeys = async (): Promise<EncryptionKeys> => {
  return new (encKeysByType[currentEncAlgorithm])({})
}
