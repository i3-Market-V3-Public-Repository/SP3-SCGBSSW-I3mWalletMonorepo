import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import { IconDefinition, faChevronRight, faChevronDown } from '@fortawesome/free-solid-svg-icons'

import { joinClassNames } from '@wallet/renderer/util'
import { useContextMenu, Menu } from '@wallet/renderer/components'

import './tree-list.scss'

export interface InterfaceObject<T = any> {
  item: T
  type: string
}

export interface TreeListItem<T> extends InterfaceObject<T> {
  text: string
  id: string
  forcedCollapse?: boolean
  icon?: IconDefinition
  iconColor?: React.CSSProperties['color']
  menu?: Menu

  parent: TreeListItem<T> | null
  children?: Array<TreeListItem<any>>

  onSelect?: (item: TreeListItem<T>) => void
  onDoubleClick?: (item: TreeListItem<T>) => void
  onToogleCollapse?: (item: TreeListItem<T>, collapsed: boolean) => boolean
}

interface Props<T> {
  items: Array<TreeListItem<T>>
  selected?: InterfaceObject
  tab?: number
  id: string
}

export function TreeList<T = string> (props: Props<T>): JSX.Element {
  const { id, items, selected } = props
  const localStorageIdentifier = `${id}.treelist.state`
  const localStorageState = localStorage.getItem(localStorageIdentifier)
  let collapsedItemsState: boolean[] = []
  if (localStorageState === null) {
    collapsedItemsState = props.items.map(() => true)
  } else {
    collapsedItemsState = JSON.parse(localStorageState)
  }

  const [collapsedItems, setCollapsedItems] = React.useState(collapsedItemsState)
  const openContextMenu = useContextMenu()
  const tab = props.tab ?? 0
  const rootProps: React.HTMLAttributes<any> = {}
  if (tab === 0) {
    rootProps.tabIndex = 0
  }

  const toogleCollapse = (item: TreeListItem<T>, index: number): void => {
    const onToogleCollapse = item.onToogleCollapse ?? (() => !collapsedItems[index])
    collapsedItems[index] = onToogleCollapse(item, collapsedItems[index])

    setCollapsedItems([...collapsedItems])
  }

  const selectItem = (item: TreeListItem<T>): void => {
    if (item.onSelect !== undefined) {
      item.onSelect(item)
    }
  }

  const contextMenu = (ev: React.MouseEvent, item: TreeListItem<T>): void => {
    ev.preventDefault()
    selectItem(item)
    if (item.menu !== undefined) {
      openContextMenu(ev, item.menu)
    }
  }

  const updateLocalStorage = (): void => {
    localStorage.setItem(localStorageIdentifier, JSON.stringify(collapsedItems))
  }
  React.useEffect(updateLocalStorage, [collapsedItems])

  return (
    <div className={joinClassNames('tree-list')} {...rootProps}>
      {items.map((item, i) => {
        const { text, children: itemChildren, forcedCollapse, icon, iconColor, onSelect, onDoubleClick } = item
        const isSelected = item.item === selected?.item
        const hasCursor = isSelected
        const collapsed = (forcedCollapse) ?? collapsedItems[i]
        const attributes: React.HTMLAttributes<HTMLDivElement> = {
          onContextMenu: (ev) => contextMenu(ev, item)
        }

        if (onSelect !== undefined) {
          attributes.onClick = () => selectItem(item)
        }
        if (onDoubleClick !== undefined) {
          attributes.onDoubleClick = () => onDoubleClick(item)
        }

        return (
          <div key={i} className='tree-list-item'>
            <div
              title={text}
              className={joinClassNames(
                'tree-list-name',
                isSelected ? 'selected' : undefined,
                hasCursor ? 'cursor' : undefined
              )}
              style={{ paddingLeft: `${(tab * 15) + 5}px` }}
              {...attributes}
            >
              {itemChildren !== undefined ? (
                <FontAwesomeIcon
                  className='tree-list-icon' icon={collapsed ? faChevronRight : faChevronDown}
                  onClick={() => toogleCollapse(item, i)}
                />
              ) : null}
              {icon !== undefined ? (
                <FontAwesomeIcon className='tree-list-icon' icon={icon} style={{ color: iconColor }} />
              ) : null}
              <span>{text}</span>
            </div>
            {(itemChildren !== undefined && !collapsed) ? (
              <TreeList id={`${id}.${item.id}`} items={itemChildren} selected={selected} tab={tab + 1} />
            ) : null}
          </div>
        )
      })}
    </div>
  )
}
