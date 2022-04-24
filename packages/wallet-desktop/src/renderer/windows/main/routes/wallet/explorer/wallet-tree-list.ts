import { faWallet, faUser, faAddressCard } from '@fortawesome/free-solid-svg-icons'
import { Identity, Resource } from '@i3m/base-wallet'

import { SharedMemory, selectWalletAction, createIdentityAction, exportResourceAction, importResourceAction, deleteResourceAction, deleteIdentityAction } from '@wallet/lib'
import { ActionDispatcher } from '@wallet/renderer/communication'
import { InterfaceObject, TreeListItem } from '@wallet/renderer/components'

interface TreeListProps {
  wallets: string[]
  sharedMemory: SharedMemory
  onSelect: (item: InterfaceObject) => void
  dispatch: ActionDispatcher
}

type WalletTreeItem = TreeListItem<string>

function getResourceProperties (resource: Resource, dispatch: ActionDispatcher): Partial<TreeListItem> {
  switch (resource.type) {
    case 'VerifiableCredential':
      return {
        icon: faAddressCard,
        text: Object
          .keys(resource.resource.credentialSubject)
          .filter((key) => key !== 'id')
          .join(', '),
        menu: {
          items: [{
            type: 'button',
            text: 'Copy ID',
            async onClick () {
              await navigator.clipboard.writeText(resource.id)
            }
          }, {
            type: 'button',
            text: 'Copy credential',
            async onClick () {
              await navigator.clipboard.writeText(JSON.stringify(resource, undefined, 2))
            }
          }, { type: 'separator' }, {
            type: 'button',
            text: 'Export...',
            onClick () {
              dispatch(exportResourceAction.create(resource.id))
            }
          }, { type: 'separator' }, {
            type: 'button',
            text: 'Delete',
            async onClick () {
              dispatch(deleteResourceAction.create(resource.id))
            }
          }]
        }
      }
  }

  return {}
}

export function buildWalletTreeList (props: TreeListProps): WalletTreeItem[] {
  const { wallets, sharedMemory, onSelect, dispatch } = props
  const walletItems: WalletTreeItem[] = []

  const dids = Object.keys(sharedMemory.identities)
  const resourceIds = Object.keys(sharedMemory.resources)
  const resources = resourceIds.map(id => sharedMemory.resources[id]) as Resource[]

  const updatePrevious = (prev: TreeListItem<any> | undefined, curr: TreeListItem<any>): TreeListItem<any> => {
    if (prev !== undefined) {
      prev.next = curr
      curr.prev = prev
    }
    return curr
  }

  let prevWallet: TreeListItem<any> | undefined
  let prevIdentity: TreeListItem<any> | undefined
  let prevResource: TreeListItem<any> | undefined
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
      forcedCollapse: wallet === sharedMemory.settings.wallet.current ? undefined : true,
      menu: {
        items: [{
          text: 'Select wallet',
          type: 'button',
          onClick () {
            dispatch(selectWalletAction.create({ wallet }))
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
          disabled: true,
          async onClick () { }
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
    prevIdentity = undefined
    prevWallet = updatePrevious(prevWallet, walletItem)

    const walletChildren: Array<TreeListItem<any>> = []
    if (wallet === sharedMemory.settings.wallet.current) {
      dids.forEach((did) => {
        const identity = sharedMemory.identities[did] as Identity
        const text = identity?.alias as string
        const identityId = `${walletId}.${text}`
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
                dispatch(deleteIdentityAction.create(identity.did))
              }
            }]
          },
          onSelect
        }
        prevResource = undefined
        prevIdentity = updatePrevious(prevIdentity, identityItem)
        walletChildren.push(identityItem)

        const identityChildren: Array<TreeListItem<any>> = identityItem.children
        resources
          .filter(resource => resource.identity === did)
          .forEach((resource) => {
            const resourceId = `${identityId}.${resource.id}`
            const resourceItem: TreeListItem<any> = {
              item: resource,
              id: resourceId,
              type: 'resource',
              text: resource.id,
              icon: faAddressCard,
              parent: identityItem,
              children: [],
              ...getResourceProperties(resource, dispatch),
              onSelect
            }
            prevResource = updatePrevious(prevResource, resourceItem)
            identityChildren.push(resourceItem)
          })
      })
    }

    walletItem.children = walletChildren
    walletItems.push(walletItem)
  })

  return walletItems
}
