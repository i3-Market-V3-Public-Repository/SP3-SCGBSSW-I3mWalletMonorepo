import * as React from 'react'

import { faLink } from '@fortawesome/free-solid-svg-icons'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import Loader from 'react-spinners/PuffLoader'

import { walletProtocolPairingAction } from '@wallet/lib'
import { useAction, useSharedMemory } from '@wallet/renderer/communication'
import { StatusBarItem } from './status-bar-item'

export function Pairing (): JSX.Element | null {
  const [sharedMemory] = useSharedMemory()
  const dispatch = useAction()
  const walletProtocol = sharedMemory.connectData.walletProtocol

  const textStyle: React.HTMLAttributes<any>['style'] = {}
  let title: string
  let icon: JSX.Element
  const onClick: (() => void) = () => {
    const action = walletProtocolPairingAction.create()
    dispatch(action)
  }

  if (walletProtocol.connectString === undefined) {
    title = 'Start Pairing'
    icon = <FontAwesomeIcon icon={faLink} className='icon' />
  } else {
    icon = <Loader size='8px' className='loader' color='white' />
    title = walletProtocol.connectString
    textStyle.fontFamily = 'monospace'
  }

  return (
    <StatusBarItem onClick={onClick}>
      {icon}
      <span style={textStyle}>{title}</span>
    </StatusBarItem>
  )
}
