import * as React from 'react'

import { joinClassNames } from '@wallet/renderer/util'

import { ResizeableDynamic } from './resizeable-dynamic'
import { ResizeableFixed } from './resizeable-fixed'

import './resizeable.scss'

type Props = React.PropsWithChildren<React.DetailedHTMLProps<React.HTMLAttributes<HTMLDivElement>, HTMLDivElement>>

export function Resizeable (props: Props): JSX.Element {
  const { className, ...divProps } = props

  return (
    <div className={joinClassNames('resizeable', className)} {...divProps}>
      {props.children}
    </div>
  )
}

Resizeable.Fixed = ResizeableFixed
Resizeable.Dynamic = ResizeableDynamic
