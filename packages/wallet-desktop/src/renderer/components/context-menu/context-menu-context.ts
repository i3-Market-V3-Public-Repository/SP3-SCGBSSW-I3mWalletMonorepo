import * as React from 'react'

import { Menu } from './context-menu-ui'

export type OpenContextMenu = (ev: React.MouseEvent, menu: Menu) => void

export type ContextMenuFunction = OpenContextMenu

export const ContextMenuContext = React.createContext<ContextMenuFunction>(() => {})
