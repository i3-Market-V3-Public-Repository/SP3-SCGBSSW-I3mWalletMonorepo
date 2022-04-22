import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import { IconDefinition, faChevronRight, faChevronDown } from '@fortawesome/free-solid-svg-icons'

import { joinClassNames } from '@wallet/renderer/util'
import { useContextMenu, Menu } from '@wallet/renderer/components'

import './tree-list.scss'
import { UseState } from '@wallet/renderer/hooks/use-presistent-state'

export interface InterfaceObject<T = any> {
  id: string
  item: T
  type: string

  parent?: TreeListItem<any>
  prev?: TreeListItem<any>
  next?: TreeListItem<any>
}

export interface TreeListItem<T = any> extends InterfaceObject<T> {
  text: string

  collapsed?: boolean
  forcedCollapse?: boolean
  icon?: IconDefinition
  iconColor?: React.CSSProperties['color']
  menu?: Menu

  showCollapseIcon?: boolean
  children: Array<TreeListItem<any>>

  onSelect?: (item: TreeListItem<T>) => void
  onDoubleClick?: (item: TreeListItem<T>) => void
  onToogleCollapse?: (item: TreeListItem<T>, collapsed: boolean) => boolean
}

interface CollapsedMap {
  [id: string]: {
    collapsed: boolean
  } | undefined
}

interface Props<T> {
  className?: string
  items: Array<TreeListItem<T>>
  selectedState: UseState<InterfaceObject | undefined>
  cursorState: UseState<string | undefined>
  collapsedState: UseState<CollapsedMap>

  listRef?: React.RefObject<HTMLDivElement>
  cursorRef?: React.RefObject<HTMLDivElement>

  tab?: number
}

function itemAggregator (prev: TreeListItem[], curr: TreeListItem): TreeListItem[] {
  return [
    ...prev,
    curr,
    ...curr.children.reduce(itemAggregator, [])
  ]
}

export function TreeList<T = string> (props: Props<T>): JSX.Element {
  const { className, items, selectedState, cursorState, collapsedState } = props
  const [selected, setSelected] = selectedState
  const [cursor, setCursor] = cursorState
  const [collapsed, setCollapsed] = collapsedState

  const listRef = props.listRef ?? React.useRef<HTMLDivElement>(null)
  const cursorRef = props.cursorRef ?? React.useRef<HTMLDivElement>(null)
  const openContextMenu = useContextMenu()
  const tab = props.tab ?? 0
  const rootProps: React.DetailedHTMLProps<React.HTMLAttributes<any>, any> = {}
  if (tab === 0) {
    const deepItems = items.reduce(itemAggregator, [])
    const cursorExecute = (id: string | undefined, cb: (item: TreeListItem) => void): void => {
      if (id === undefined) {
        return
      }
      deepItems.filter(item => item.id === id).forEach(cb)
    }

    const fixScroll = (): void => {
      if (listRef.current === null || cursorRef.current === null) {
        return
      }
      const list = listRef.current
      const cursor = cursorRef.current
      const normalizedCursorTop = cursor.offsetTop - list.offsetTop - list.scrollTop

      if (normalizedCursorTop < 0) {
        list.scrollTop = cursor.offsetTop - list.offsetTop
      } else if (normalizedCursorTop + cursor.offsetHeight > list.clientHeight) {
        list.scrollTop = cursor.offsetTop - list.offsetTop + cursor.offsetHeight - list.clientHeight
      }
    }

    rootProps.ref = listRef
    rootProps.tabIndex = 0
    rootProps.onKeyDown = (ev) => {
      switch (ev.key) {
        case 'ArrowUp': {
          ev.preventDefault()
          cursorExecute(cursor, (cursor) => {
            const prev = cursor.prev
            if (prev !== undefined) {
              const isCollapsed = isItemCollapsed(prev)
              if (!isCollapsed && prev.children.length > 0) {
                setCursor(prev.children[prev.children.length - 1].id)
              } else {
                setCursor(prev.id)
              }
            } else {
              const parentId = cursor.parent?.id
              if (parentId !== undefined) {
                setCursor(parentId)
              }
            }
          })
          break
        }

        case 'ArrowDown': {
          ev.preventDefault()
          cursorExecute(cursor, (cursor) => {
            const isCollapsed = isItemCollapsed(cursor)
            const child = cursor.children[0]
            const next = cursor.next
            const parent = cursor.parent
            if (!isCollapsed && child !== undefined) {
              setCursor(child.id)
            } else if (next !== undefined) {
              setCursor(next.id)
            } else if (parent !== undefined) {
              const nextParentId = parent.next?.id
              if (nextParentId !== undefined) {
                setCursor(nextParentId)
              }
            }
          })
          break
        }

        case 'ArrowLeft':
          cursorExecute(cursor, (cursor) => {
            const isCollapsed = isItemCollapsed(cursor)
            const parent = cursor.parent
            if (!isCollapsed) {
              ev.preventDefault()
              toogleCollapse(cursor)
            } else if (parent !== undefined) {
              ev.preventDefault()
              setCursor(parent.id)
            }
          })
          break

        case 'ArrowRight':
          cursorExecute(cursor, (cursor) => {
            const isCollapsed = isItemCollapsed(cursor)
            const child = cursor.children[0]
            if (isCollapsed) {
              ev.preventDefault()
              toogleCollapse(cursor)
            } else if (child !== undefined) {
              ev.preventDefault()
              setCursor(child.id)
            }
          })
          break

        case 'Enter':
          if (cursor !== undefined) {
            cursorExecute(cursor, selectItem)
          }
          break

        case 'Escape':
          console.log('unselect')
          setSelected(undefined)
          break
      }
    }

    React.useLayoutEffect(fixScroll)
  }

  const isItemCollapsed = (item: TreeListItem<T>): boolean => {
    if (item.forcedCollapse !== undefined) {
      return item.forcedCollapse
    }

    const collapsedItem = collapsed[item.id]
    if (collapsedItem !== undefined) {
      return collapsedItem.collapsed
    }
    return true
  }

  const toogleCollapse = (item: TreeListItem<T>): void => {
    const collapsedItem = isItemCollapsed(item)
    const onToogleCollapse = item.onToogleCollapse ?? (() => !collapsedItem)
    const collapsedResult = onToogleCollapse(item, collapsedItem)

    setCollapsed({
      ...collapsed,
      [item.id]: {
        ...collapsed[item.id],
        collapsed: collapsedResult
      }
    })

    setSelected(item)
  }

  const selectItem = (item: TreeListItem<any>): void => {
    if (item.onSelect !== undefined) {
      setCursor(item.id)
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

  return (
    <div className={joinClassNames('tree-list', className)} {...rootProps}>
      {items.map((item, i) => {
        const { text, children: itemChildren, forcedCollapse, icon, iconColor, showCollapseIcon, onSelect, onDoubleClick } = item
        const isSelected = item.id === selected?.id
        const hasCursor = item.id === cursor
        const collapsed = (forcedCollapse) ?? isItemCollapsed(item)
        const extraParams: React.DetailedHTMLProps<React.HTMLAttributes<HTMLDivElement>, HTMLDivElement> = {
          onContextMenu: (ev) => contextMenu(ev, item)
        }

        if (onSelect !== undefined) {
          extraParams.onClick = () => selectItem(item)
        }
        if (onDoubleClick !== undefined) {
          extraParams.onDoubleClick = () => onDoubleClick(item)
        }

        if (hasCursor) {
          extraParams.ref = cursorRef
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
              {...extraParams}
            >
              {itemChildren.length > 0 || showCollapseIcon === true ? (
                <FontAwesomeIcon
                  className='tree-list-icon' icon={collapsed ? faChevronRight : faChevronDown}
                  onClick={() => toogleCollapse(item)}
                />
              ) : null}
              {icon !== undefined ? (
                <FontAwesomeIcon className='tree-list-icon' icon={icon} style={{ color: iconColor }} />
              ) : null}
              <span>{text}</span>
            </div>
            {(itemChildren !== undefined && !collapsed) ? (
              <TreeList listRef={listRef} cursorRef={cursorRef} items={itemChildren} selectedState={selectedState} cursorState={cursorState} collapsedState={collapsedState} tab={tab + 1} />
            ) : null}
          </div>
        )
      })}
    </div>
  )
}
