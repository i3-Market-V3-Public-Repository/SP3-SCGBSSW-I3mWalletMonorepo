import * as React from 'react'

import { joinClassNames } from '@wallet/renderer/util'

import './horizontal-accordion.scss'

type AccordionProps = React.DetailedHTMLProps<React.HTMLAttributes<HTMLDivElement>, HTMLDivElement>

export function Extendible (props: AccordionProps): JSX.Element {
  const { className, ...extraProps } = props

  return (
    <div className={joinClassNames('accordion-extendible', className)} {...extraProps}>
      {props.children}
    </div>
  )
}
