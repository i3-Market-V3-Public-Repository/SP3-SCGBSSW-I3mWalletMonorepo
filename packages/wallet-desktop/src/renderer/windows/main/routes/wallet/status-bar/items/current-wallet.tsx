import * as React from 'react'

import { faWallet } from '@fortawesome/free-solid-svg-icons'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'

import { selectWalletAction } from '@wallet/lib'
import { useSharedMemory, useAction } from '@wallet/renderer/communication'
import { StatusBarItem } from './status-bar-item'

export function CurrentWallet (): JSX.Element | null {
  const [sharedMemory] = useSharedMemory()
  const dispatch = useAction()

  const currentWallet = sharedMemory.settings.public.currentWallet

  const onClick = (): void => {
    dispatch(selectWalletAction.create())
  }

  return currentWallet !== undefined ? (
    <StatusBarItem onClick={onClick}>
      <FontAwesomeIcon icon={faWallet} className='icon' />
      <span>{currentWallet}</span>
    </StatusBarItem>
  ) : null
}
