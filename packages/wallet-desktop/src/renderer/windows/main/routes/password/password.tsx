
import * as ReactRouterDOM from 'react-router-dom'
import * as React from 'react'

import { useOutput, useSharedMemory } from '@wallet/renderer/communication'

import './password.scss'

const { Redirect } = ReactRouterDOM

interface State {
  password: string
}

export function Password (): JSX.Element {
  const [state, setState] = React.useState<State>({
    password: ''
  })

  const output$ = useOutput()
  const [sharedMemory] = useSharedMemory()
  if (sharedMemory.hasStore) {
    console.log('Redirect, password already set')
    return <Redirect to='/wallet' />
  }

  const handleChange: React.ChangeEventHandler<HTMLInputElement> = (ev) => {
    setState({ password: ev.target.value })
  }

  const handleSubmit: React.MouseEventHandler = (ev): void => {
    ev.preventDefault()
    output$.next({
      type: 'password',
      value: state.password
    })
  }

  return (
    <div className='password-route'>
      <form className='password-form'>
        <div className='group-form-field'>
          <input
            type='password' className='form-field' placeholder='Name'
            name='password' autoFocus value={state.password}
            onChange={handleChange} required
          />
          <label htmlFor='password' className='form-label'>Password</label>
        </div>
        {/* <input type='password' /> */}
        <button className='modern' type='submit' onClick={handleSubmit}>
          Send password
        </button>
      </form>
    </div>
  )
}
