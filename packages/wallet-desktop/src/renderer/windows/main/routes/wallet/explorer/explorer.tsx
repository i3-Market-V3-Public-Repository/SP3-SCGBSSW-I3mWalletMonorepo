import { faPlus, faWallet, faUser, faFile } from '@fortawesome/free-solid-svg-icons'

import { Identity, Resource } from '@i3m/base-wallet'

import { selectWalletAction, createWalletAction, createIdentityAction } from '@wallet/lib'
import { useSharedMemory, useAction } from '@wallet/renderer/communication'
import { Section, ListSelector, HorizontalAccordion, Fixed, DividerOperation, TreeList, TreeListItem, InterfaceObject } from '@wallet/renderer/components'
import { Details } from './details'

import './explorer.scss'

export function Explorer (): JSX.Element {
  const [sharedMemory] = useSharedMemory()
  const dispatch = useAction()

  const [selectedIdentity, setSelectedIdentity] = React.useState<string | undefined>(undefined)
  const [selectedWallet, setSelectedWallet] = React.useState<string | undefined>(undefined)
  const [selectedResource, setSelectedResource] = React.useState<string | undefined>(undefined)
  const [selected, setSelected] = React.useState<InterfaceObject | undefined>(undefined)

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
  const resources = resourceIds.map(id => sharedMemory.resources[id]) as Resource[]
  let resource: Resource | undefined
  if (selectedResource !== undefined) {
    resource = sharedMemory.resources[selectedResource]
  }

  // Actions
  const selectWallet = (current: string): void => {
    dispatch(selectWalletAction.create({ wallet: current }))
    setSelectedWallet(current)
    setSelectedIdentity(undefined)
    setSelectedResource(undefined)
    setSelected({ type: 'wallet', item: current })
  }

  const selectIdentity = (current: string): void => {
    setSelectedWallet(undefined)
    setSelectedIdentity(current)
    setSelectedResource(undefined)
    setSelected({ type: 'identity', item: sharedMemory.identities[current] })
  }

  const selectResource = (current: string): void => {
    setSelectedWallet(undefined)
    setSelectedIdentity(undefined)
    setSelectedResource(current)
    setSelected({ type: 'resource', item: sharedMemory.resources[current] })
  }

  const onSelect = (item: InterfaceObject): void => {
    setSelected(item)
  }

  const getIdentitiesForWallet = (wallet: string): Array<TreeListItem<any>> | undefined => {
    if (wallet !== sharedMemory.settings.wallet.current) {
      return []
    }

    return dids.map((did) => {
      const children = resources
        .filter(resource => resource.identity === did)
        .map((resource) => ({
          item: resource,
          id: resource.id,
          type: 'resource',
          text: resource.id,
          icon: faFile,
          parent: null,
          onSelect
        }))

      const text = sharedMemory.identities[did]?.alias as string

      return {
        item: sharedMemory.identities[did],
        type: 'identity',
        text,
        id: text,
        icon: faUser,
        parent: null,
        children: children.length > 0 ? children : undefined,
        onSelect
      }
    })
  }

  const items = wallets.map((wallet) => {
    const item: TreeListItem<string> = {
      item: wallet,
      id: wallet,
      type: 'wallet',
      text: wallet,
      icon: faWallet,
      forcedCollapse: wallet === sharedMemory.settings.wallet.current ? undefined : true,
      parent: null,
      children: getIdentitiesForWallet(wallet),
      menu: {
        items: [{
          text: 'Select wallet',
          onClick () {
            dispatch(selectWalletAction.create({ wallet }))
          }
        }, {
          text: 'Create identity...',
          onClick () {
            dispatch(selectWalletAction.create({ wallet }))
            dispatch(createIdentityAction.create())
          }
        }]
      },
      onSelect,
      onDoubleClick (walletItem) {
        dispatch(selectWalletAction.create({ wallet: walletItem.item }))
      },
      onToogleCollapse (walletItem, collapsed: boolean) {
        if (wallet !== sharedMemory.settings.wallet.current) {
          dispatch(selectWalletAction.create({ wallet: walletItem.item }))
          return false
        }
        return !collapsed
      }
    }
    return item
  })

  return (
    <HorizontalAccordion className='explorer'>
      <Fixed className='explorer-content'>
        <div style={{ display: 'none' }}>
          <Section title='Wallets' operations={walletOperations}>
            <ListSelector selected={selectedWallet} items={wallets} onSelect={selectWallet} />
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
        </div>
        <Section title='Wallets' operations={walletOperations}>
          <div className='scroll'>
            <TreeList id='wallets' items={items} selected={selected} />
          </div>
        </Section>
      </Fixed>
      <Details item={selected} />
    </HorizontalAccordion>
  )
}
