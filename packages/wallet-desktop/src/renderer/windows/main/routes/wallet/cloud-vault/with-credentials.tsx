
import * as React from 'react'
import { Card } from 'react-bootstrap'

import { Credentials } from '@wallet/lib'

interface Props {
  credentials: Credentials
}

export function WithCredentials (props: Props): JSX.Element {
  const { credentials } = props

  return (
    <Card style={{ width: '18rem' }}>
      <Card.Body>
        <Card.Title>You have credentials!</Card.Title>
        <Card.Text>
          But there was a problem with the login. You can try to login with the same credentials ({credentials.username}) or logout.
        </Card.Text>
      </Card.Body>
    </Card>
  )
}
