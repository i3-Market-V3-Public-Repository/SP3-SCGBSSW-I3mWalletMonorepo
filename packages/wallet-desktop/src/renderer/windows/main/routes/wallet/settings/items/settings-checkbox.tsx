import _ from 'lodash'
import * as React from 'react'
import { Form } from 'react-bootstrap'

import { useAction, useSharedMemory } from '@wallet/renderer/communication'
import { executeFunctionOrValue } from '../execute-function-or-value'
import { CheckboxSettingsMetadata } from '../settings-metadata'

interface Props {
  metadata: CheckboxSettingsMetadata
}

export function SettingsCheckbox (props: Props): JSX.Element {
  const { metadata } = props

  const dispatch = useAction()
  const [sharedMemory, setSharedMemory] = useSharedMemory()
  const value: boolean = _.get(sharedMemory.settings, metadata.key) ?? false
  const label = executeFunctionOrValue(metadata.label, metadata, value, sharedMemory)
  const id = `settings-${label}`

  const onChange = (): void => {
    const newValue = !value
    console.log('change', newValue)
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
      <label htmlFor={id}>{label}</label>
      <Form.Switch id={id} onChange={onChange} checked={value} />
    </>
  )
}
