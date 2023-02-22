import { faCheck, faXmark, IconDefinition } from '@fortawesome/free-solid-svg-icons'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'

import { startCloudSyncAction, stopCloudSyncAction } from '@wallet/lib'
import { useAction, useSharedMemory } from '@wallet/renderer/communication'
import { StatusBarItem } from './status-bar-item'

export function CloudVault (): JSX.Element | null {
  const [sharedMemory] = useSharedMemory()
  const dispatch = useAction()

  let title: string
  let icon: IconDefinition
  let onClick: (() => void) | undefined
  const { state } = sharedMemory.cloudVaultData
  if (state === 'connected') {
    title = 'Cloud Vault'
    icon = faCheck
    onClick = () => {
      dispatch(stopCloudSyncAction.create())
    }
  } else {
    title = 'Cloud Vault'
    icon = faXmark
    onClick = () => {
      dispatch(startCloudSyncAction.create())
    }
  }

  return (
    <StatusBarItem onClick={onClick}>
      <FontAwesomeIcon icon={icon} className='icon' />
      <span>{title}</span>
    </StatusBarItem>
  )
}
