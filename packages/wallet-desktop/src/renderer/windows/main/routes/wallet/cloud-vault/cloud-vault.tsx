
import * as React from 'react'
import { VaultState } from '@i3m/cloud-vault-client'
import { Alert, Button, ButtonProps } from 'react-bootstrap'

import { DEFAULT_CLOUD_URL, logoutCloudAction, registerCloudAction, reloginCloudAction, stopCloudSyncAction, syncCloudAction, toVaultState } from '@wallet/lib'
import { useAction, useSharedMemory } from '@wallet/renderer/communication'
import { Details, Section } from '@wallet/renderer/components'

import './cloud-vault.scss'

type Operation = (() => void) | undefined
interface CloudVaultOperations {
  login?: Operation
  register?: Operation
  logout?: Operation
  sync?: Operation
  delete?: Operation
}

const bindOperation = (operation: keyof CloudVaultOperations, operations: CloudVaultOperations): ButtonProps => {
  const props: ButtonProps = {}
  if (operations[operation] !== undefined) {
    props.onClick = operations[operation]
  } else {
    props.disabled = true
  }

  return props
}

const getStateText = (state: VaultState): string => {
  switch (state) {
    case toVaultState('connected'):
      return 'Connected'

    default:
      return 'Disconnected'
  }
}

export function CloudVault (): JSX.Element {
  const [mem] = useSharedMemory()
  const dispatch = useAction()
  const { cloudVaultData: publicCloudData } = mem
  const { cloud: privateCloudData } = mem.settings

  const state = publicCloudData.state
  const username = privateCloudData?.credentials?.username
  const url = privateCloudData?.url ?? DEFAULT_CLOUD_URL
  const unsynced = publicCloudData.unsyncedChanges
  const operations: CloudVaultOperations = {}

  const onLogin = (): void => {
    dispatch(reloginCloudAction.create())
  }

  const onRegister = (): void => {
    dispatch(registerCloudAction.create())
  }

  const onLogout = (): void => {
    dispatch(logoutCloudAction.create())
  }

  const onDelete = (): void => {
    dispatch(stopCloudSyncAction.create())
  }

  const onSync = (): void => {
    dispatch(syncCloudAction.create())
  }

  if (!publicCloudData.loggingIn) {
    if (state === toVaultState('connected')) {
      operations.logout = onLogout
      operations.sync = onSync
      operations.delete = onDelete
    } else if (privateCloudData?.credentials !== undefined) {
      operations.login = onLogin
      operations.logout = onLogout
    } else {
      operations.login = onLogin
      operations.register = onRegister
    }
  }

  return (
    <Section className='cloud-vault' title='Cloud Vault' scroll light center>
      <Details>
        <Details.Body>
          {unsynced ? <Alert variant='warning'>Your wallet is currently <b>unsynced</b>!</Alert> : null}
          <Details.Title>Summary</Details.Title>
          <Details.Grid>
            <Details.Input label='Status' value={getStateText(state)} />
            {username !== undefined ? <Details.Input label='Username' value={username} /> : null}
            <Details.Input label='URL' value={url} />
          </Details.Grid>
        </Details.Body>
        <Details.Separator />
        <Details.Body>
          <Details.Grid>
            <Details.Buttons title='Cloud connection'>
              <Button {...bindOperation('login', operations)}>Login</Button>
              <Button {...bindOperation('register', operations)}>Register</Button>
              <Button {...bindOperation('logout', operations)} variant='danger'>Logout</Button>
            </Details.Buttons>
            <Details.Buttons title='Cloud actions'>
              <Button {...bindOperation('sync', operations)}>Force sync</Button>
              <Button {...bindOperation('delete', operations)} variant='danger'>Delete cloud</Button>
            </Details.Buttons>
          </Details.Grid>
        </Details.Body>
      </Details>
    </Section>
  )
}
