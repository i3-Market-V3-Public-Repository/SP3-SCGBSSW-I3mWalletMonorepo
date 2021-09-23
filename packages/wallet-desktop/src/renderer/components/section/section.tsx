import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import { IconDefinition } from '@fortawesome/free-solid-svg-icons'

import { joinClassNames } from '@wallet/renderer/util'

import './section.scss'

export interface DividerOperation {
  icon: IconDefinition
  onClick: () => void
}

type Props = React.PropsWithChildren<{
  title: string
  operations?: DividerOperation[]
}>

export function Section (props: Props): JSX.Element {
  const operations = props.operations ?? []
  const { title, children } = props

  return (
    <div className={joinClassNames('section')}>
      <div className='header'>
        <span className='label'>{title}</span>
        {operations.map(({ icon, onClick }, i) => (
          <FontAwesomeIcon
            key={i} className='operation-icon'
            icon={icon} onClick={onClick}
          />
        ))}
      </div>
      {children}
    </div>
  )
}
