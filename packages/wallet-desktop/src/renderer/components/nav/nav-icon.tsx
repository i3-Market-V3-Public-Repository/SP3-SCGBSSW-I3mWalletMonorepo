import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import { IconDefinition } from '@fortawesome/free-solid-svg-icons'

import { joinClassNames } from '@wallet/renderer/util'

export interface NavIconProps {
  icon: IconDefinition
  title: string
  path: string
}

export function NavIcon (props: NavIconProps): JSX.Element {
  const history = ReactRouterDOM.useHistory()
  const location = ReactRouterDOM.useLocation()
  const { icon, path, title } = props
  const active = props.path.startsWith(location.pathname)

  return (
    <div
      className={joinClassNames('nav-icon-container', active ? 'active' : undefined)}
      onClick={() => history.push(path)}
      title={title}
    >
      <FontAwesomeIcon className='nav-icon' icon={icon} />
      <div className='nav-icon-background' />
    </div>
  )
}
