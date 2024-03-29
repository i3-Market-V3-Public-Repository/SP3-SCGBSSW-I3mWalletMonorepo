import * as React from 'react'

import { faPlus } from '@fortawesome/free-solid-svg-icons'

import { createWalletAction } from '@wallet/lib'
import { useAction, useSharedMemory } from '@wallet/renderer/communication'
import { DividerOperation, InterfaceObject, Resizeable, Section, TreeList } from '@wallet/renderer/components'
import { usePresistentState } from '@wallet/renderer/hooks'
import { DetailsSwitch } from './details-switch'

import './explorer.scss'
import { buildWalletTreeList } from './wallet-tree-list'

interface ExplorerTreeViewState {
  [id: string]: {
    collapsed: boolean
  } | undefined
}

export function Explorer (): JSX.Element {
  const [sharedMemory] = useSharedMemory()
  const dispatch = useAction()
  const listRef = React.useRef<HTMLDivElement>(null)
  const selectedState = React.useState<InterfaceObject | undefined>(undefined)
  const cursorState = React.useState<string | undefined>(undefined)
  const treeViewState = usePresistentState<ExplorerTreeViewState>('explorerTreeView.state', {})

  const [selected, setSelected] = selectedState
  const [, setCursor] = cursorState

  const walletOperations: DividerOperation[] = []
  walletOperations.push({
    icon: faPlus,
    onClick: () => dispatch(createWalletAction.create())
  })

  const onSelect = (item: InterfaceObject): void => {
    setSelected(item)
  }

  const onDelete = (): void => {
    setSelected(undefined)
    setCursor(undefined)
  }

  const wallet = sharedMemory.settings.private.wallet
  const wallets = Object.keys(wallet.wallets)
  const items = buildWalletTreeList({
    wallets, sharedMemory, onSelect, onDelete, dispatch
  })

  return (
    <Resizeable className='explorer'>
      <Resizeable.Dynamic className='explorer-content' stateId='wallet.explorer.tree-list' resizeWidth>
        <Section title='Explorer' operations={walletOperations} scrollRef={listRef} scroll>
          <TreeList
            listRef={listRef} items={items}
            selectedState={selectedState}
            cursorState={cursorState}
            collapsedState={treeViewState}
            paddingBottom={15}
          />
        </Section>
      </Resizeable.Dynamic>
      <Resizeable.Fixed>
        <DetailsSwitch title='' light scroll center item={selected} />
      </Resizeable.Fixed>
    </Resizeable>
  )
}
