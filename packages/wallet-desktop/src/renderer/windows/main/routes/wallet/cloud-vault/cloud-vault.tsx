
import { VaultState } from '@i3m/cloud-vault-client'
import * as React from 'react'
import { Alert, Button, ButtonProps } from 'react-bootstrap'

import { clientRestartAction, DEFAULT_CLOUD_URL, deleteCloudAction, logoutCloudAction, registerCloudAction, reloginCloudAction, stopCloudAction, syncCloudAction, toVaultState } from '@wallet/lib'
import { useAction, useSharedMemory } from '@wallet/renderer/communication'
import { Details, ExternalLink, Section } from '@wallet/renderer/components'

import './cloud-vault.scss'

type Operation = (() => void) | undefined
interface CloudVaultOperations {
  login?: Operation
  register?: Operation
  logout?: Operation
  sync?: Operation
  delete?: Operation
  restart?: Operation
  stop?: Operation
}

const bindOperation = (operation: keyof CloudVaultOperations, operations: CloudVaultOperations): ButtonProps => {
  const props: ButtonProps = {}
  if (operations[operation] !== undefined) {
    props.onClick = operations[operation]
  } else {
    props.style = { display: 'none' }
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
  const { cloud: privateCloudSettings } = mem.settings.private
  const { cloud: publicCloudSettings } = mem.settings.public

  const state = publicCloudData.state
  const username = privateCloudSettings?.credentials?.username
  const url = publicCloudSettings?.url ?? DEFAULT_CLOUD_URL
  const unsynced = publicCloudData.unsyncedChanges
  const registration = publicCloudData.registration
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
    dispatch(deleteCloudAction.create())
  }

  const onSync = (): void => {
    dispatch(syncCloudAction.create())
  }

  const onStop = (): void => {
    dispatch(stopCloudAction.create())
  }

  const onRestart = (): void => {
    dispatch(clientRestartAction.create())
  }

  if (!publicCloudData.loggingIn) {
    if (state === toVaultState('connected')) {
      operations.logout = onLogout
      operations.sync = onSync
      operations.delete = onDelete
    } else if (privateCloudSettings?.credentials !== undefined) {
      operations.login = onLogin
      operations.logout = onLogout
    } else {
      operations.login = onLogin
      operations.register = onRegister
    }
  } else {
    operations.restart = onRestart
    operations.stop = onStop
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
        {registration !== undefined ? (
          <Details.Body>
            <Details.Title>Register</Details.Title>
            <Alert>
              You started the registartion process for the user "{registration.username}". Please, click this <ExternalLink href={registration.url}>link</ExternalLink> to
              finish it. After your account is properly created, you have to login using the button bellow.
            </Alert>
            <Details.Grid>
              <Details.Input label='Username' value={registration.username} />
              <Details.Input label='Registration URL' value={registration.url} />
            </Details.Grid>
          </Details.Body>
        ) : null}
        <Details.Separator />
        <Details.Body>
          <Details.Grid>
            {/* <Details.Buttons title='Cloud connection'>
            </Details.Buttons> */}
            <Details.Buttons title='Cloud actions'>
              <Button {...bindOperation('login', operations)}>Login</Button>
              <Button {...bindOperation('register', operations)}>Register</Button>
              {/* <Button {...bindOperation('restart', operations)} variant='danger'>Restart Client</Button> */}
              <Button {...bindOperation('sync', operations)}>Force sync</Button>
              <Button {...bindOperation('logout', operations)} variant='danger'>Logout</Button>
              <Button {...bindOperation('delete', operations)} variant='danger'>Delete cloud</Button>
              <Button {...bindOperation('stop', operations)} variant='danger'>Stop</Button>
            </Details.Buttons>
          </Details.Grid>
        </Details.Body>
      </Details>
    </Section>
  )
}
