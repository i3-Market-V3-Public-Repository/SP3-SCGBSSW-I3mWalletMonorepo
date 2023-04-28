import * as React from 'react'
import { OverlayTrigger, Tooltip } from 'react-bootstrap'
import { OverlayInjectedProps } from 'react-bootstrap/esm/Overlay'
import { faCheck, faExclamationTriangle, faXmark } from '@fortawesome/free-solid-svg-icons'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import Loader from 'react-spinners/PuffLoader'

import { toVaultState } from '@wallet/lib'
import { useSharedMemory } from '@wallet/renderer/communication'

import { StatusBarItem } from './status-bar-item'

export function CloudVault (): JSX.Element | null {
  const [sharedMemory] = useSharedMemory()
  // const dispatch = useAction()

  const title = 'Cloud Vault'
  let icon: JSX.Element | null = null
  let onClick: (() => void) | undefined
  let tooltip: string = 'Unknown state'
  const { state, syncing } = sharedMemory.cloudVaultData
  const unsyncedChanges = sharedMemory.settings.public.cloud?.unsyncedChanges ?? false

  if (syncing) {
    icon = <Loader size='20px' className='loader' color='white' />
    tooltip = 'Syncing'
  } else if (state < toVaultState('connected')) {
    icon = <FontAwesomeIcon icon={faXmark} className='icon' />
    tooltip = 'Disconnected'
  } else if (unsyncedChanges) {
    icon = <FontAwesomeIcon icon={faExclamationTriangle} className='icon' />
    tooltip = 'Not synced'
  } else if (state >= toVaultState('connected')) {
    icon = <FontAwesomeIcon icon={faCheck} className='icon' />
    tooltip = 'Connected'
  }

  const renderTooltip = (props: OverlayInjectedProps): JSX.Element => (
    <Tooltip id='button-tooltip' {...props}>
      {tooltip}
    </Tooltip>
  )

  return (
    <OverlayTrigger
      placement='top'
      delay={{ show: 250, hide: 400 }}
      overlay={renderTooltip}
    >
      <StatusBarItem onClick={onClick}>
        {icon}
        <span>{title}</span>
      </StatusBarItem>
    </OverlayTrigger>
  )
}
