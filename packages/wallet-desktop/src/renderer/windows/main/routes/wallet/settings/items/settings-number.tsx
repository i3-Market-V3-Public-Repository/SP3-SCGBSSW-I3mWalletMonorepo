import * as React from 'react'

import { useAction, useSharedMemory } from '@wallet/renderer/communication'
import _ from 'lodash'
import { Form } from 'react-bootstrap'
import { executeFunctionOrValue } from '../execute-function-or-value'
import { NumberSettingsMetadata } from '../settings-metadata'

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
    <>
      <label htmlFor={id} title={label}>{label}</label>
      <Form.Control id={id} type='number' size='sm' onChange={onChange} value={value} />
    </>
  )
}
