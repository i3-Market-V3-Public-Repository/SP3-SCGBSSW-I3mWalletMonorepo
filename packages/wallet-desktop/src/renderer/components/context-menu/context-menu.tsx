import { ContextMenuUI, ContextMenuData } from './context-menu-ui'
import { ContextMenuContext, OpenContextMenu } from './context-menu-context'

export function ContextMenu (props: React.PropsWithChildren<{}>): JSX.Element {
  const [ctx, setCtx] = React.useState<ContextMenuData | undefined>()
  const openContextMenu: OpenContextMenu = (ev, menu) => {
    setCtx({
      contextMenu: menu,
      x: ev.pageX,
      y: ev.pageY
    })
  }

  const closeDialog = (): void => {
    setCtx(undefined)
  }

  React.useEffect(() => {
    window.addEventListener('mousedown', closeDialog)
    return () => {
      window.removeEventListener('mousedown', closeDialog)
    }
  }, [])

  return (
    <ContextMenuContext.Provider value={openContextMenu}>
      <ContextMenuUI ctx={ctx} onClose={closeDialog} />
      {props.children}
    </ContextMenuContext.Provider>
  )
}
