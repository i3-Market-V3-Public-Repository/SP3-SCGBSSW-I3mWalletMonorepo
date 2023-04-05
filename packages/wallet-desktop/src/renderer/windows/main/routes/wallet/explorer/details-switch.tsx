import * as React from 'react'

import { useSharedMemory } from '@wallet/renderer/communication'
import { InterfaceObject, Section, SectionProps } from '@wallet/renderer/components'

import { IdentityDetails } from './identity'
import { ResourceDetails } from './resource'
import { WalletDetails } from './wallet'

export interface Props extends SectionProps {
  item?: InterfaceObject
}

export function DetailsSwitch (props: Props): JSX.Element | null {
  const { item, ...sectionProps } = props
  const [sharedMemory] = useSharedMemory()

  let children: JSX.Element

  switch (item?.type) {
    case 'wallet': {
      const wallet = sharedMemory.settings.private.wallet
      const walletInfo = wallet.wallets[item.item]
      children = <WalletDetails wallet={walletInfo} {...sectionProps} />
      break
    }
    case 'identity': {
      children = <IdentityDetails identity={item.item} {...sectionProps} />
      break
    }
    case 'resource': {
      children = <ResourceDetails item={item.item} {...sectionProps} />
      break
    }
    default:
      return <Section {...sectionProps} />
  }

  return children
}
