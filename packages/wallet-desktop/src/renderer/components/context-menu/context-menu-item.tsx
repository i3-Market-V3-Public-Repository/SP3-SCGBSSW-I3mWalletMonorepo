import * as React from 'react'

import { joinClassNames } from '@wallet/renderer/util'

export interface ContextMenuButton {
  text: string
  type: 'button'
  disabled?: boolean
  onClick: () => void
}

export interface ContextMenuSeparator {
  type: 'separator'
}

export type ContextMenuItem = ContextMenuButton | ContextMenuSeparator

interface Props {
  item: ContextMenuItem
  onClose: () => void
}

export function ContextMenuItemUI (props: Props): JSX.Element | null {
  const { item, onClose } = props

  switch (item.type) {
    case 'button':
      return (
        <span
          className={joinClassNames('button', item.disabled === true ? 'disabled' : undefined)}
          onClick={(ev) => {
            if (item.disabled !== true) {
              item.onClick()
              onClose()
            }
          }}
        >{item.text}
        </span>
      )
    case 'separator':
      return <span className='separator' />
  }

  return null
}
