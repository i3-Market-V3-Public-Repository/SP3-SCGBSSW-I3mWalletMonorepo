import { Provider, SharedMemory } from '@wallet/lib'

export function getProvider (didMethod: string | undefined, sharedMemory: SharedMemory): Provider | undefined {
  return [
    ...sharedMemory.settings.private.providers,
    // TODO: Fix this
    {
      name: 'i3Market',
      network: 'i3m'
    }
  ].find((provider) => `did:ethr:${provider.network}` === didMethod)
}
