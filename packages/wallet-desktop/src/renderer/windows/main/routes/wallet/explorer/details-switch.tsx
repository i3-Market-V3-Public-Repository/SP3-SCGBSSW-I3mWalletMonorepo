import * as React from 'react'

import { useSharedMemory } from '@wallet/renderer/communication'
import { InterfaceObject, Section } from '@wallet/renderer/components'

import { IdentityDetails } from './identity'
import { ResourceDetails } from './resource'
import { WalletDetails } from './wallet'

export interface Props {
  item?: InterfaceObject
}

export function DetailsSwitch (props: Props): JSX.Element | null {
  const { item } = props
  const [sharedMemory] = useSharedMemory()

  let children: JSX.Element

  switch (item?.type) {
    case 'wallet': {
      const wallet = sharedMemory.settings.wallet
      const walletInfo = wallet.wallets[item.item]
      children = <WalletDetails wallet={walletInfo} />
      break
    }
    case 'identity': {
      children = <IdentityDetails identity={item.item} />
      break
    }
    case 'resource': {
      children = <ResourceDetails resource={item.item} />
      break
    }
    default:
      return <Section title='' light />
  }

  return children
}
