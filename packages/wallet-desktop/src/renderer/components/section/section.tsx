import * as React from 'react'

import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import { IconDefinition } from '@fortawesome/free-solid-svg-icons'

import { joinClassNames } from '@wallet/renderer/util'

import './section.scss'

export interface DividerOperation {
  icon: IconDefinition
  onClick: () => void
}

type DivProps = React.DetailedHTMLProps<React.HTMLAttributes<HTMLDivElement>, HTMLDivElement>
type Props = React.PropsWithChildren<{
  title: string
  light?: boolean
  scroll?: boolean
  scrollRef?: React.LegacyRef<HTMLDivElement>
  operations?: DividerOperation[]
} & DivProps>

export function Section (props: Props): JSX.Element {
  const operations = props.operations ?? []
  const { className, title, children, light, scroll, scrollRef, ...divProps } = props
  const scrollClass = scroll === true ? 'scroll' : undefined
  const lightClass = light === true ? 'light' : undefined

  return (
    <div className={joinClassNames('section', className, lightClass)} {...divProps}>
      <div className='header'>
        <span className='label' title={title}>{title}</span>
        {operations.map(({ icon, onClick }, i) => (
          <FontAwesomeIcon
            key={i} className='operation-icon'
            icon={icon} onClick={onClick}
          />
        ))}
      </div>
      <div className={joinClassNames('body', scrollClass)} ref={scrollRef}>
        {children}
      </div>
    </div>
  )
}
