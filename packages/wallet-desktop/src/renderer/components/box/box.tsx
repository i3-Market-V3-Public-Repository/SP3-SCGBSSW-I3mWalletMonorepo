import { joinClassNames } from '@wallet/renderer/util'
import * as React from 'react'

import './box.scss'

interface Props extends React.DetailedHTMLProps<React.HTMLAttributes<HTMLDivElement>, HTMLDivElement> {
  title: string
}

export function Box (props: React.PropsWithChildren<Props>): JSX.Element {
  const { title, children, className, ...extraProps } = props

  return (
    <div className={joinClassNames('box', className)} {...extraProps}>
      <div className='header'>
        <span className='title'>{title}</span>
      </div>
      <div className='body scroll vertical'>
        {children}
      </div>
    </div>
  )
}
