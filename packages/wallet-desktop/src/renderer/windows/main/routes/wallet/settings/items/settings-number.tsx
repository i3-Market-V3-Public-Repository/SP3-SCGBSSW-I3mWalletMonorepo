import * as React from 'react'

import _ from 'lodash'
import { useAction, useSharedMemory } from '@wallet/renderer/communication'
import { NumberSettingsMetadata } from '../settings-metadata'
import { Col, Form, Row } from 'react-bootstrap'
import { executeFunctionOrValue } from '../execute-function-or-value'

interface Props {
  metadata: NumberSettingsMetadata
}

export function SettingsNumber (props: Props): JSX.Element {
  const { metadata } = props

  const dispatch = useAction()
  const [sharedMemory, setSharedMemory] = useSharedMemory()
  const value = _.get(sharedMemory.settings, metadata.key) ?? 0
  const label = executeFunctionOrValue(metadata.label, metadata, value, sharedMemory)
  const id = `settings-${label}`

  const onChange: React.ChangeEventHandler<HTMLInputElement> = (ev) => {
    const newValue = ev.target.valueAsNumber
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
    <Form.Group as={Row} className='settings-number' controlId={id}>
      <Form.Label column sm='2'>{label}</Form.Label>
      <Col sm='10'>
        <Form.Control type='number' size='sm' onChange={onChange} value={value} />
      </Col>
    </Form.Group>
  )
}
