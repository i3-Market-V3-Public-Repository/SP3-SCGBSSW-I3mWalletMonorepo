
import * as React from 'react'

import { logoutCloudAction, stopCloudSyncAction } from '@wallet/lib'
import { useAction } from '@wallet/renderer/communication'
import { Button, ButtonGroup, Card } from 'react-bootstrap'

export function Authenticated (): JSX.Element {
  const dispatch = useAction()

  const onLogout = (): void => {
    dispatch(logoutCloudAction.create())
  }

  const onDelete = (): void => {
    dispatch(stopCloudSyncAction.create())
  }

  return (
    <Card style={{ width: '18rem' }}>
      <Card.Body>
        <Card.Title>Authenticated!</Card.Title>
        <Card.Text>
          You are connected to the vault __URL__
          With the username __USER__
        </Card.Text>
        <ButtonGroup vertical>
          <Button onClick={onLogout}>Logout</Button>
          <Button variant='danger' onClick={onDelete}>Delete cloud storage</Button>
        </ButtonGroup>
      </Card.Body>
    </Card>
  )
}
