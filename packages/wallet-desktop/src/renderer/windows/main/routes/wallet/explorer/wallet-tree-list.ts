import { faAddressCard, faCode, faFileSignature, faKey, faQuestionCircle, faReceipt, faRightLeft, faUser, faWallet } from '@fortawesome/free-solid-svg-icons'
import { Identity, Resource } from '@i3m/base-wallet'

import { createIdentityAction, deleteIdentityAction, deleteResourceAction, deleteWalletAction, exportResourceAction, importResourceAction, selectWalletAction, SharedMemory } from '@wallet/lib'
import { ActionDispatcher } from '@wallet/renderer/communication'
import { InterfaceObject, Menu, TreeListItem } from '@wallet/renderer/components'
import { ContextMenuItem } from '@wallet/renderer/components/context-menu/context-menu-item'
import { getResourceName } from '@wallet/renderer/util'

type ItemEventHandler = (item: InterfaceObject) => void
type DeleteEventHandler = () => void

interface TreeListProps {
  wallets: string[]
  sharedMemory: SharedMemory
  onDelete: DeleteEventHandler
  onSelect: ItemEventHandler
  dispatch: ActionDispatcher
}

type WalletTreeItem = TreeListItem<string>

function buildResourceTreeListItem (props: TreeListProps, parent: TreeListItem<any>, resource: Resource, resources: Resource[]): TreeListItem<any> {
  const { onSelect, dispatch } = props
  const resourceId = `${parent.id}.${resource.id}`
  const resourceChildren: Array<TreeListItem<any>> = []
  const resourceItem: TreeListItem<any> = {
    item: resource,
    id: resourceId,
    type: 'resource',
    text: getResourceName(resource),
    icon: faQuestionCircle,
    parent,
    children: resourceChildren,
    ...getResourceProperties(props, resource, dispatch),
    onSelect
  }

  resources
    .filter(child => resource.id === child.parentResource)
    .map((child) => buildResourceTreeListItem(props, resourceItem, child, resources))
    .forEach((child) => resourceChildren.push(child))

  sortTreeListItem(resourceChildren)

  return resourceItem
}

function getResourceProperties (props: TreeListProps, resource: Resource, dispatch: ActionDispatcher): Partial<TreeListItem> {
  const menuCopyItems: ContextMenuItem[] = [
    {
      type: 'button',
      text: 'Copy ID',
      async onClick () {
        await navigator.clipboard.writeText(resource.id)
      }
    },
    {
      type: 'button',
      text: 'Copy resource',
      async onClick () {
        await navigator.clipboard.writeText(JSON.stringify(resource, undefined, 2))
      }
    }
  ]
  const menuExportItems: ContextMenuItem[] = [{
    type: 'button',
    text: 'Export...',
    onClick () {
      dispatch(exportResourceAction.create(resource.id))
    }
  }]
  const menuDeleteItems: ContextMenuItem[] = [{
    type: 'button',
    text: 'Delete',
    async onClick () {
      props.onDelete()
      dispatch(deleteResourceAction.create(resource.id))
    }
  }]

  const menu: Menu = {
    items: [
      ...menuCopyItems,
      { type: 'separator' },
      ...menuExportItems,
      { type: 'separator' },
      ...menuDeleteItems
    ]
  }

  switch (resource.type) {
    case 'VerifiableCredential':
      return {
        icon: faAddressCard,
        text: Object
          .keys(resource.resource.credentialSubject)
          .filter((key) => key !== 'id')
          .join(', '),
        menu
      }

    case 'Object':
      return {
        icon: faCode,
        menu
      }

    case 'KeyPair':
      return {
        icon: faKey,
        menu
      }

    case 'Contract':
      return {
        icon: faFileSignature,
        menu
      }
    case 'DataExchange':
      return {
        icon: faRightLeft,
        menu
      }

    case 'NonRepudiationProof':
      return {
        icon: faReceipt,
        menu
      }
  }

  return {}
}

function sortTreeListItem (list: TreeListItem[]): void {
  const compareTreeListItem = (a: TreeListItem, b: TreeListItem): number => {
    if (a.text.toLowerCase() > b.text.toLowerCase()) {
      return 1
    }
    if (b.text.toLowerCase() > a.text.toLowerCase()) {
      return -1
    }
    return 0
  }

  const updatePrevious = (prev: TreeListItem<any> | undefined, curr: TreeListItem<any>): TreeListItem<any> => {
    if (prev !== undefined) {
      prev.next = curr
      curr.prev = prev
    }
    return curr
  }

  let prev: TreeListItem | undefined
  list.sort(compareTreeListItem).forEach((curr) => {
    prev = updatePrevious(prev, curr)
  })
}

export function buildWalletTreeList (props: TreeListProps): WalletTreeItem[] {
  const { wallets, sharedMemory, onSelect, dispatch } = props
  const walletItems: WalletTreeItem[] = []

  const dids = Object.keys(sharedMemory.identities)
  const resourceIds = Object.keys(sharedMemory.resources)
  const resources = resourceIds.map(id => sharedMemory.resources[id]) as Resource[]

  wallets.forEach((wallet) => {
    // Build wallet tree item
    const walletId = wallet
    const walletItem: TreeListItem<any> = {
      item: wallet,
      id: walletId,
      type: 'wallet',
      text: wallet,
      icon: faWallet,
      children: [],
      showCollapseIcon: true,
      forcedCollapse: wallet === sharedMemory.settings.private.wallet.current ? undefined : true,
      menu: {
        items: [{
          text: 'Select wallet',
          type: 'button',
          onClick () {
            dispatch(selectWalletAction.create({ wallet }))
          }
        }, { type: 'separator' }, {
          type: 'button',
          text: 'Import resource...',
          async onClick () {
            dispatch(importResourceAction.create(undefined))
          }
        }, {
          text: 'Create identity...',
          type: 'button',
          onClick () {
            dispatch(selectWalletAction.create({ wallet }))
            dispatch(createIdentityAction.create())
          }
        }, { type: 'separator' }, {
          type: 'button',
          text: 'Copy name',
          async onClick () {
            await navigator.clipboard.writeText(wallet)
          }
        }, { type: 'separator' }, {
          type: 'button',
          text: 'Delete',
          // disabled: true,
          async onClick () {
            props.onDelete()
            dispatch(deleteWalletAction.create(wallet))
          }
        }]
      },
      onSelect,
      onDoubleClick (walletItem) {
        dispatch(selectWalletAction.create({ wallet: walletItem.item }))
      },
      onToogleCollapse (walletItem, collapsed: boolean) {
        if (wallet !== sharedMemory.settings.private.wallet.current) {
          dispatch(selectWalletAction.create({ wallet: walletItem.item }))
          return false
        }
        return !collapsed
      }
    }

    const walletChildren: Array<TreeListItem<any>> = []
    if (wallet === sharedMemory.settings.private.wallet.current) {
      dids.forEach((did) => {
        const identity = sharedMemory.identities[did] as Identity
        const text = identity?.alias as string
        const identityId = `${walletId}.${identity.did}`
        const identityItem: TreeListItem<any> = {
          item: identity,
          type: 'identity',
          text,
          id: identityId,
          icon: faUser,
          parent: walletItem,
          children: [],
          menu: {
            items: [{
              text: 'Copy DID',
              type: 'button',
              async onClick () {
                await navigator.clipboard.writeText(identity.did)
              }
            }, {
              text: 'Copy ethereum address',
              type: 'button',
              async onClick () {
                const address = ethers.utils.computeAddress(`0x${identity.keys[0].publicKeyHex}`)
                await navigator.clipboard.writeText(address)
              }
            }, { type: 'separator' }, {
              type: 'button',
              text: 'Import resource...',
              async onClick () {
                dispatch(importResourceAction.create(identity.did))
              }
            }, { type: 'separator' }, {
              type: 'button',
              text: 'Delete',
              async onClick () {
                props.onDelete()
                dispatch(deleteIdentityAction.create(identity.did))
              }
            }]
          },
          onSelect
        }
        walletChildren.push(identityItem)

        const identityChildren: Array<TreeListItem<any>> = identityItem.children
        resources
          .filter(resource => resource.identity === did && resource.parentResource === undefined)
          .map((resource) => buildResourceTreeListItem(props, identityItem, resource, resources))
          .forEach((resource) => identityChildren.push(resource))

        sortTreeListItem(identityChildren)
      })

      resources
        .filter(resource => resource.identity === undefined && resource.parentResource === undefined)
        .map((resource) => buildResourceTreeListItem(props, walletItem, resource, resources))
        .forEach((resource) => walletChildren.push(resource))
    }

    sortTreeListItem(walletChildren)
    walletItem.children = walletChildren
    walletItems.push(walletItem)
  })

  sortTreeListItem(walletItems)
  return walletItems
}
