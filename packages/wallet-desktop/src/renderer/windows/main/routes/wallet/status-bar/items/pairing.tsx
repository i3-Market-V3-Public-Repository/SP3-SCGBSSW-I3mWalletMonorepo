import * as React from 'react'

import { faLink } from '@fortawesome/free-solid-svg-icons'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import Loader from 'react-spinners/PuffLoader'

import { walletProtocolPairingAction } from '@wallet/lib'
import { useAction, useSharedMemory } from '@wallet/renderer/communication'
import { StatusBarItem } from './status-bar-item'
import { OverlayTrigger, Tooltip } from 'react-bootstrap'
import { OverlayInjectedProps } from 'react-bootstrap/esm/Overlay'

export function Pairing (): JSX.Element | null {
  const [sharedMemory] = useSharedMemory()
  const dispatch = useAction()
  const walletProtocol = sharedMemory.connectData.walletProtocol

  const renderTooltip = (props: OverlayInjectedProps): JSX.Element => (
    <Tooltip id='button-tooltip' {...props}>
      Start pairing protocol
    </Tooltip>
  )

  const textStyle: React.HTMLAttributes<any>['style'] = {}
  let title: string
  let icon: JSX.Element
  const onClick: (() => void) = () => {
    const action = walletProtocolPairingAction.create()
    dispatch(action)
  }

  if (walletProtocol.connectString === undefined) {
    title = 'Connect'
    icon = <FontAwesomeIcon icon={faLink} className='icon' />
  } else {
    icon = <Loader size='20px' className='loader' color='white' />
    title = walletProtocol.connectString
    textStyle.fontFamily = 'monospace'
  }

  return (
    <OverlayTrigger
      placement='top'
      delay={{ show: 250, hide: 400 }}
      overlay={renderTooltip}
    >
      <StatusBarItem onClick={onClick}>
        {icon}
        <span style={textStyle}>{title}</span>
      </StatusBarItem>
    </OverlayTrigger>
  )
}
