import _ from 'lodash'
import * as React from 'react'

import { useAction, useSharedMemory } from '@wallet/renderer/communication'

import { executeFunctionOrValue } from '../execute-function-or-value'
import { AutocompleteSettingsMetadata } from '../settings-metadata'
import { Autocomplete } from '@wallet/renderer/components'

interface Props {
  metadata: AutocompleteSettingsMetadata
}

export function SettingsAutocomplete (props: Props): JSX.Element {
  const { metadata } = props

  const dispatch = useAction()
  const [sharedMemory, setSharedMemory] = useSharedMemory()
  const value = _.get(sharedMemory.settings, metadata.key) ?? ''
  const label = executeFunctionOrValue(metadata.label, metadata, value, sharedMemory)
  const options = metadata.options
  const id = `settings-${label}`
  const placeholder = metadata.placeholder

  const onChange = (label: string): void => {
    const newValue: string = label
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
      <Autocomplete id={id} placeholder={placeholder} options={options} getLabel={(v) => v} onChange={onChange} value={value} />
    </>
  )
}
