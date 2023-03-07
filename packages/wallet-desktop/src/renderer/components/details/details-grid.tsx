import * as React from 'react'

import { joinClassNames } from '@wallet/renderer/util'

type Props = React.PropsWithChildren<React.DetailedHTMLProps<React.HTMLAttributes<HTMLDivElement>, HTMLDivElement>>

export function DetailsGrid (props: Props): JSX.Element {
  const { className, ...divProps } = props

  return (
    <div className={joinClassNames('details-grid', className)} {...divProps}>
      {props.children}
    </div>
  )
}
