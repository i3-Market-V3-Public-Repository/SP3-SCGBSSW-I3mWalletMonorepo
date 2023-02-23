import { faCheck, faXmark } from '@fortawesome/free-solid-svg-icons'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import Loader from 'react-spinners/PuffLoader'

import { startCloudSyncAction, stopCloudSyncAction } from '@wallet/lib'
import { useAction, useSharedMemory } from '@wallet/renderer/communication'
import { StatusBarItem } from './status-bar-item'

export function CloudVault (): JSX.Element | null {
  const [sharedMemory] = useSharedMemory()
  const dispatch = useAction()

  const title = 'Cloud Vault'
  let icon: JSX.Element
  let onClick: (() => void) | undefined
  const { state } = sharedMemory.cloudVaultData
  if (state === 'connected') {
    icon = <FontAwesomeIcon icon={faCheck} className='icon' />
    onClick = () => {
      dispatch(stopCloudSyncAction.create())
    }
  } else if (state === 'sync') {
    icon = <Loader size='8px' className='loader' color='white' />
  } else {
    icon = <FontAwesomeIcon icon={faXmark} className='icon' />
    onClick = () => {
      dispatch(startCloudSyncAction.create())
    }
  }

  return (
    <StatusBarItem onClick={onClick}>
      {icon}
      <span>{title}</span>
    </StatusBarItem>
  )
}
