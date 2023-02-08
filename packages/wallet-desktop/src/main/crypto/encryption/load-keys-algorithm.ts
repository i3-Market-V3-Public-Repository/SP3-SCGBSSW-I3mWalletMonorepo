import { AuthSettings, EncSettings, EncSettingsAlgorithms } from '@wallet/lib'
import { EncryptionKeys, EncryptionKeysConstructor } from '../key-generators'

import { Pbkdf2EncKeys } from './pbkdf2'
import { GenericPbkdfEncKeys } from './generic-pbkdf'

type EncKeysMap = {
  [K in EncSettingsAlgorithms]: EncryptionKeysConstructor<K>
}

const encKeysByType: EncKeysMap = {
  'pbkdf.2': Pbkdf2EncKeys,
  'generic-pbkdf': GenericPbkdfEncKeys
}

export const currentEncAlgorithm: EncSettingsAlgorithms = 'generic-pbkdf'

export const loadEncKeyAlgorithm = (auth?: AuthSettings, enc?: EncSettings): EncryptionKeys => {
  if (enc === undefined) {
    if (auth === undefined) {
      const EncKeysType = (encKeysByType[currentEncAlgorithm])
      return EncKeysType.initialize()
    }

    // When there is no enc data but there is auth data means that the settings are form an older version
    // This version had Pbkdf2 for the enc keys and auth keys with the same salt
    return Pbkdf2EncKeys.fromAuth(auth)
  }

  const EncKeysType = (encKeysByType[enc.algorithm]) as EncryptionKeysConstructor<typeof enc.algorithm>
  return new EncKeysType(enc)
}

export const getCurrentEncKeys = async (): Promise<EncryptionKeys> => {
  return (encKeysByType[currentEncAlgorithm]).initialize()
}
