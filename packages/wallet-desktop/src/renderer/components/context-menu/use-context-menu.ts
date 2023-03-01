import * as React from 'react'

import { ContextMenuContext, OpenContextMenu } from './context-menu-context'

export const useContextMenu = (): OpenContextMenu =>
  React.useContext(ContextMenuContext)
