import { AuthSettingsAlgorithms, BaseAuthSettings } from '@wallet/lib'
import { AuthenticationKeys, AuthenticationKeysConstructor } from '../key-generators'
import { Pbkdf2AuthKeys } from './pbkdf2'

const authKeysByType: Record<AuthSettingsAlgorithms, AuthenticationKeysConstructor> = {
  'pbkdf.2': Pbkdf2AuthKeys
}

export const loadAuthKeyAlgorithm = (auth?: BaseAuthSettings): AuthenticationKeys => {
  if (auth === undefined) {
    return new (authKeysByType[currentAuthAlgorithm])({})
  }

  const algorithm = auth.algorithm ?? 'pbkdf.2'
  return new (authKeysByType[algorithm])(auth)
}

export const currentAuthAlgorithm: AuthSettingsAlgorithms = 'pbkdf.2'

export const getCurrentAuthKeys = async (): Promise<AuthenticationKeys> => {
  return new (authKeysByType[currentAuthAlgorithm])({})
}
