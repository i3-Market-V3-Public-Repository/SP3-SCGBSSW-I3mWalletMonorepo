import * as React from 'react'

import _ from 'lodash'
import { useAction, useSharedMemory } from '@wallet/renderer/communication'

import { InputSettingsMetadata } from '../settings-metadata'
import { Col, Form, Row } from 'react-bootstrap'
import { executeFunctionOrValue } from '../execute-function-or-value'

interface Props {
  metadata: InputSettingsMetadata
}

export function SettingsInput (props: Props): JSX.Element {
  const { metadata } = props

  const dispatch = useAction()
  const [sharedMemory, setSharedMemory] = useSharedMemory()
  const value = _.get(sharedMemory.settings, metadata.key) ?? ''
  const label = executeFunctionOrValue(metadata.label, metadata, value, sharedMemory)
  const id = `settings-${label}`

  const onChange: React.ChangeEventHandler<HTMLInputElement> = (ev) => {
    const newValue = ev.target.value
    if (metadata.canUpdate !== undefined && !metadata.canUpdate(metadata.key, newValue, metadata, sharedMemory, dispatch)) {
      return
    }

    const newSettings: any = {}
    _.set(newSettings, metadata.key, newValue)
    setSharedMemory({
      settings: newSettings
    })
  }

  return (
    <Form.Group as={Row} className='settings-input' controlId={id}>
      <Form.Label column sm='2'>{label}</Form.Label>
      <Col sm='10'>
        <Form.Control type='text' size='sm' placeholder={metadata.placeholder} onChange={onChange} value={value} />
      </Col>
    </Form.Group>
  )
}
