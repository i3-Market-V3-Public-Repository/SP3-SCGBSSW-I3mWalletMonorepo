import { AuthSettingsAlgorithms, AuthSettings } from '@wallet/lib'
import { AuthenticationKeys, AuthenticationKeysConstructor } from '../key-generators'
import { Pbkdf2AuthKeys } from './pbkdf2'

type DefinedAlgorithms = AuthSettingsAlgorithms & string

type AuthKeysMap = {
  [K in DefinedAlgorithms]: AuthenticationKeysConstructor<K>
}

const authKeysByType: AuthKeysMap = {
  'pbkdf.2': Pbkdf2AuthKeys
}

export const currentAuthAlgorithm: DefinedAlgorithms = 'pbkdf.2'

export const loadAuthKeyAlgorithm = (auth?: AuthSettings): AuthenticationKeys => {
  if (auth === undefined) {
    const AuthKeysType = authKeysByType[currentAuthAlgorithm]
    return AuthKeysType.initialize()
  }

  if (auth.algorithm === undefined) {
    return new Pbkdf2AuthKeys({
      ...auth,
      algorithm: 'pbkdf.2'
    })
  }

  const AuthKeysType = authKeysByType[auth.algorithm]
  return new AuthKeysType(auth)
}

export const getCurrentAuthKeys = async (): Promise<AuthenticationKeys> => {
  return (authKeysByType[currentAuthAlgorithm]).initialize()
}
