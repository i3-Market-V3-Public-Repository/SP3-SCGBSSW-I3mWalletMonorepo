
import * as React from 'react'

import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import { faLink } from '@fortawesome/free-solid-svg-icons'
import { walletProtocolPairingAction } from '@wallet/lib'
import { HorizontalAccordion } from '@wallet/renderer/components'
import { useSharedMemory, useAction } from '@wallet/renderer/communication'
import { joinClassNames } from '@wallet/renderer/util'

import './connect.scss'
import { Wave } from './wave'

export function Connect (): JSX.Element {
  // const [pairing, setPairing] = React.useState(false)
  const dispatch = useAction()
  const [mem] = useSharedMemory()
  const pairing = mem.connectData.walletProtocol.connectString !== undefined
  let message = 'Click the button to start the protocol...'
  let pin: string | undefined
  if (pairing) {
    message = 'Pairing... PIN:'
    pin = mem.connectData.walletProtocol.connectString as string
  }

  const startPairing = (): void => {
    const action = walletProtocolPairingAction.create()
    dispatch(action)
  }

  return (
    <HorizontalAccordion className='connect'>
      <div className='center-vertically'>
        <div className={joinClassNames(
          'wallet-protocol',
          'connect-box',
          pairing ? 'pairing' : undefined
        )}
        >
          <span className='title'>You can connect applications using the wallet protocol</span>
          <span className='message'>{message}</span>
          <span className='pin'>{pin}</span>
          <div className='sync'>
            <div className='radar'>
              <Wave />
              <div className='circle one' />
              <div className='circle two' />
              <div className='circle three' />
            </div>
            <div className='sync-button' onClick={startPairing}>
              <FontAwesomeIcon icon={faLink} />
            </div>
          </div>
        </div>
      </div>
    </HorizontalAccordion>
  )
}
