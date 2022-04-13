
import './context-menu.scss'

export interface ContextMenuItem {
  text: string
  onClick: () => void
}

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
  const { ctx } = props
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
        <span
          onClick={(ev) => {
            item.onClick()
            props.onClose()
          }} key={i}
        >{item.text}
        </span>
      ))}
    </div>
  )
}
