import { faPlus } from '@fortawesome/free-solid-svg-icons'

import { createWalletAction } from '@wallet/lib'
import { useSharedMemory, useAction } from '@wallet/renderer/communication'
import { Section, HorizontalAccordion, Resizeable, DividerOperation, TreeList, InterfaceObject } from '@wallet/renderer/components'
import { usePresistentState } from '@wallet/renderer/hooks'
import { Details } from './details'

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

  const wallet = sharedMemory.settings.wallet
  const wallets = Object.keys(wallet.wallets)
  const items = buildWalletTreeList({
    wallets, sharedMemory, onSelect, onDelete, dispatch
  })

  return (
    <HorizontalAccordion className='explorer'>
      <Resizeable className='explorer-content' stateId='wallet.explorer.tree-list' resizeWidth>
        <Section title='Wallets' operations={walletOperations}>
          <div className='scroll' ref={listRef}>
            <TreeList
              listRef={listRef} items={items}
              selectedState={selectedState}
              cursorState={cursorState}
              collapsedState={treeViewState}
            />
          </div>
        </Section>
      </Resizeable>
      <Details item={selected} />
    </HorizontalAccordion>
  )
}
