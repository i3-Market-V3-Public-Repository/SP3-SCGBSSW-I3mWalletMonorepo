import { faPlus } from '@fortawesome/free-solid-svg-icons'
import { Identity, Resource } from '@i3-market/base-wallet'

import { selectWalletAction, createWalletAction, createIdentityAction } from '@wallet/lib'
import { useSharedMemory, useAction } from '@wallet/renderer/communication'
import { Section, ListSelector, HorizontalAccordion, Fixed, DividerOperation } from '@wallet/renderer/components'
import { IdentityDetails } from './identity'
import { ResourceDetails } from './resource'

import './wallets.scss'

export function Wallets (): JSX.Element {
  const [sharedMemory] = useSharedMemory()
  const dispatch = useAction()

  const [selectedIdentity, setSelectedIdentity] = React.useState<string | undefined>(undefined)
  const [selectedResource, setSelectedResource] = React.useState<string | undefined>(undefined)

  const wallet = sharedMemory.settings.wallet
  const wallets = Object.keys(wallet.wallets)

  const walletOperations: DividerOperation[] = []
  walletOperations.push({
    icon: faPlus,
    onClick: () => dispatch(createWalletAction.create())
  })

  const dids = Object.keys(sharedMemory.identities)
  let identity: Identity | undefined
  if (selectedIdentity !== undefined) {
    identity = sharedMemory.identities[selectedIdentity]
  }

  const identityOperations: DividerOperation[] = []
  identityOperations.push({
    icon: faPlus,
    onClick: () => dispatch(createIdentityAction.create())
  })

  const resourceIds = Object.keys(sharedMemory.resources)
  let resource: Resource | undefined
  if (selectedResource !== undefined) {
    resource = sharedMemory.resources[selectedResource]
  }

  // Actions

  const selectWallet = (current: string): void => {
    dispatch(selectWalletAction.create(current))
    setSelectedIdentity(undefined)
    setSelectedResource(undefined)
  }

  const selectIdentity = (current: string): void => {
    setSelectedIdentity(current)
    setSelectedResource(undefined)
  }

  const selectResource = (current: string): void => {
    setSelectedIdentity(undefined)
    setSelectedResource(current)
  }

  return (
    <HorizontalAccordion className='wallets'>
      <Fixed className='wallet-content'>
        <Section title='Wallets' operations={walletOperations}>
          <ListSelector selected={wallet.current} items={wallets} onSelect={selectWallet} />
        </Section>
        <Section title='Identities' operations={identityOperations}>
          <ListSelector
            selected={identity?.did}
            items={dids}
            getText={(did) => sharedMemory.identities[did]?.alias as string}
            onSelect={(did) => selectIdentity(did)}
          />
        </Section>
        <Section title='Credentials'>
          <ListSelector
            selected={resource?.id}
            items={resourceIds}
            onSelect={(id) => selectResource(id)}
          />
        </Section>
      </Fixed>
      {identity !== undefined ? <IdentityDetails identity={identity} /> : null}
      {resource !== undefined ? <ResourceDetails resource={resource} /> : null}
    </HorizontalAccordion>
  )
}
