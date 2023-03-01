import * as React from 'react'

import { useSharedMemory } from '@wallet/renderer/communication'
import { Extendible, InterfaceObject } from '@wallet/renderer/components'

import { IdentityDetails } from './identity'
import { ResourceDetails } from './resource'
import { WalletDetails } from './wallet'

export interface Props {
  item?: InterfaceObject
}

export function Details (props: Props): JSX.Element | null {
  const { item } = props
  if (item === undefined) {
    return <Extendible className='details' />
  }

  const [sharedMemory] = useSharedMemory()
  switch (item.type) {
    case 'wallet': {
      const wallet = sharedMemory.settings.wallet
      const walletInfo = wallet.wallets[item.item]
      return <WalletDetails wallet={walletInfo} />
    }
    case 'identity': {
      return <IdentityDetails identity={item.item} />
    }
    case 'resource': {
      return <ResourceDetails resource={item.item} />
    }
    default:
      return null
  }
}
