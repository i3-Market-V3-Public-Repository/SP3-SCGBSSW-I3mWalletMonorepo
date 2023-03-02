
import * as React from 'react'

import { Button } from 'react-bootstrap'
import { loginCloudAction, registerCloudAction } from '@wallet/lib'
import { useAction } from '@wallet/renderer/communication'

export function Authenticate (): JSX.Element {
  const dispatch = useAction()

  const onLogin = (): void => {
    dispatch(loginCloudAction.create())
  }

  const onRegister = (): void => {
    dispatch(registerCloudAction.create())
  }

  return (
    <>
      <div>You are not authenticated!</div>
      <div className='login'>
        If you already have an account click here to login
      </div>
      <Button onClick={onLogin}>Login</Button>
      <div>Or</div>
      <div className='register'>
        Click here to start the registration process
      </div>
      <button onClick={onRegister}>Register</button>
    </>
  )
}