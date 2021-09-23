import { IconDefinition } from '@fortawesome/fontawesome-svg-core'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import { joinClassNames } from '@wallet/renderer/util'

type Props = React.PropsWithChildren<{
  icon?: IconDefinition
  onClick?: () => void
}>

export function StatusBarItem (props: Props): JSX.Element {
  const icon = props.icon
  const clickable = props.onClick !== undefined
  const onClick = props.onClick ?? (() => {})

  return (
    <div className={joinClassNames('status-bar-item', clickable ? 'clickable' : undefined)} onClick={onClick}>
      {icon !== undefined ? <FontAwesomeIcon className='icon' icon={icon} /> : null}
      {props.children}
    </div>
  )
}
