import * as React from 'react'

import './content.scss'

export function Content (props: React.PropsWithChildren<{}>): JSX.Element {
  return (
    <div className='content'>
      {props.children}
    </div>
  )
}
