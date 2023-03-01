
import * as React from 'react'
import { joinClassNames } from '@wallet/renderer/util'

type DivAttributes = React.DetailedHTMLProps<React.HTMLAttributes<HTMLDivElement>, HTMLDivElement>
export function Bootstrap (props: React.PropsWithChildren<DivAttributes>): JSX.Element {
  const { children, className, ...divProps } = props

  return (
    <div className={joinClassNames('bootstrap', className)} {...divProps}>
      {children}
    </div>
  )
}
