import { ContextMenuItem, ContextMenuItemUI } from './context-menu-item'

import './context-menu.scss'

export interface Menu {
  items: ContextMenuItem[]
}

export interface ContextMenuData {
  contextMenu: Menu
  x: number
  y: number
}

interface Props {
  ctx?: ContextMenuData
  onClose: () => void
}

export function ContextMenuUI (props: Props): JSX.Element | null {
  const { ctx, onClose } = props
  if (ctx === undefined) {
    return null
  }

  const { contextMenu, x, y } = ctx
  // TODO: Fix x and y to appear inside the window!
  return (
    <div
      className='context-menu'
      style={{ left: `${x}px`, top: `${y - 10}px` }}
      onMouseDown={(ev) => ev.stopPropagation()}
    >
      {contextMenu.items.map((item, i) => (
        <ContextMenuItemUI key={i} onClose={onClose} item={item} />
      ))}
    </div>
  )
}
