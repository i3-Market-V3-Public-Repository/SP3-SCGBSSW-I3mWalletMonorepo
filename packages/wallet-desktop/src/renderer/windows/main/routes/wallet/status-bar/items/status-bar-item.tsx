import * as React from 'react'

import { joinClassNames } from '@wallet/renderer/util'

type Props = React.PropsWithChildren<React.DetailedHTMLProps<React.HTMLAttributes<HTMLDivElement>, HTMLDivElement>>

export const StatusBarItem = React.forwardRef<HTMLDivElement, Props>((props, ref): JSX.Element => {
  const clickable = props.onClick !== undefined
  const { className, ...divProps } = props

  return (
    <div ref={ref} className={joinClassNames('status-bar-item', className, clickable ? 'clickable' : undefined)} {...divProps}>
      {props.children}
    </div>
  )
})
