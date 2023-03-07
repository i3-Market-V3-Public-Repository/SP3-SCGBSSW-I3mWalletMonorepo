import * as React from 'react'

import { joinClassNames } from '@wallet/renderer/util'

type Props = React.PropsWithChildren<React.DetailedHTMLProps<React.HTMLAttributes<HTMLSpanElement>, HTMLSpanElement>>

export function DetailsTitle (props: Props): JSX.Element {
  const { className, ...divProps } = props

  return (
    <span className={joinClassNames('details-title', className)} {...divProps}>
      {props.children}
    </span>
  )
}
