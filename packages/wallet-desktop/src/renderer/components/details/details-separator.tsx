import * as React from 'react'

import { joinClassNames } from '@wallet/renderer/util'

type Props = React.DetailedHTMLProps<React.HTMLAttributes<HTMLDivElement>, HTMLDivElement>

export function DetailsSeparator (props: Props): JSX.Element {
  const { className, ...divProps } = props

  return (
    <div className={joinClassNames('details-separator', className)} {...divProps} />
  )
}
