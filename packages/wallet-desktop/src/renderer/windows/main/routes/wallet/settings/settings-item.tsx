import * as React from 'react'

import { faPlus } from '@fortawesome/free-solid-svg-icons'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import _ from 'lodash'

import { useAction, useSharedMemory } from '@wallet/renderer/communication'

import { Accordion, CloseButton } from 'react-bootstrap'
import { executeFunctionOrValue } from './execute-function-or-value'
import { SettingsCheckbox, SettingsInput, SettingsNumber } from './items'
import { SettingsDescription } from './settings-description'
import { ArraySettingsMetadata, ItemMetadata, ObjectSettingsMetadata, SettingsMetadata } from './settings-metadata'

interface Props {
  metadata: ItemMetadata
}

interface ArrayProps {
  metadata: ArraySettingsMetadata
}

interface ObjectProps {
  metadata: ObjectSettingsMetadata
}

function ArraySettingsItem (props: ArrayProps): JSX.Element {
  const { metadata } = props

  const [sharedMemory, setSharedMemory] = useSharedMemory()
  const dispatch = useAction()
  const values: any[] = _.get(sharedMemory.settings, metadata.key) ?? []
  const label = executeFunctionOrValue(metadata.label, metadata, values, sharedMemory)

  const onAddClick: React.MouseEventHandler = (ev) => {
    const newSettings: any = {}
    _.set(newSettings, metadata.key, [
      ...values,
      metadata.defaults(metadata, values)
    ])

    setSharedMemory({
      settings: newSettings
    })
  }

  const onDeleteClick = (i: number) => (): void => {
    if (metadata.canDelete !== undefined && !metadata.canDelete(i, values[i], sharedMemory, dispatch)) {
      // Errors should be shown using dispatch inside canDelete method!
      return
    }

    const newSettings: any = {}
    values.splice(i, 1)
    _.set(newSettings, metadata.key, [...values])
    setSharedMemory({
      settings: newSettings
    })
  }

  const buildChildMetadata = (i: number): SettingsMetadata => {
    const childMetadata = metadata.innerType(i, metadata)

    // Proxy canUpdateMethod
    const childCanUpdate = childMetadata.canUpdate
    const newChildCanUpdate: typeof childMetadata['canUpdate'] = (key, value, childMetadata, sharedMemory, dispatch) => {
      let res = true
      if (childCanUpdate !== undefined) {
        res &&= childCanUpdate(key, value, childMetadata, sharedMemory, dispatch)
      }

      if (metadata.canUpdate !== undefined) {
        res &&= metadata.canUpdate(key, value, metadata, sharedMemory, dispatch)
      }

      return res
    }
    childMetadata.canUpdate = newChildCanUpdate

    return childMetadata
  }

  return (
    <div className='settings-array'>
      <div className='settings-array-header'>
        <label>{label}</label>
        <FontAwesomeIcon className='settings-array-button add-button' icon={faPlus} onClick={onAddClick} />
      </div>
      <Accordion flush alwaysOpen>
        {values.map((item, i) => (
          <div className='settings-array-item' key={i}>
            <SettingsItem metadata={buildChildMetadata(i)} />
            <CloseButton className='settings-array-button delete-button' onClick={onDeleteClick(i)} />
          </div>
        ))}
      </Accordion>
    </div>
  )
}

function ObjectSettingsItem (props: ObjectProps): JSX.Element {
  const { metadata } = props

  const properties = Object
    .keys(metadata.innerType)
    .sort((a, b) => a > b ? 1 : b > a ? -1 : 0)

  const [sharedMemory] = useSharedMemory()
  const key = metadata.key
  const value = _.get(sharedMemory.settings, metadata.key) ?? {} as any
  const label = executeFunctionOrValue(metadata.label, metadata, value, sharedMemory)

  const buildPropMetadata = (propKey: string): SettingsMetadata => {
    const propMetadata = metadata.innerType[propKey]
    if (propMetadata === undefined) {
      throw new Error('Cannot find property')
    }

    // Proxy canUpdateMethod
    const propCanUpdate = propMetadata.canUpdate
    const newPropCanUpdate: typeof propMetadata['canUpdate'] = (key, value, propMetadata, sharedMemory, dispatch) => {
      let res = true
      if (propCanUpdate !== undefined) {
        res &&= propCanUpdate(key, value, propMetadata, sharedMemory, dispatch)
      }

      if (metadata.canUpdate !== undefined) {
        res &&= metadata.canUpdate(key, value, metadata, sharedMemory, dispatch)
      }

      return res
    }
    propMetadata.canUpdate = newPropCanUpdate

    return propMetadata
  }

  return (
    <Accordion.Item className='settings-object' eventKey={key}>
      <Accordion.Header className='settings-object-header'>
        {label}
      </Accordion.Header>
      <Accordion.Body className='settings-items'>
        {properties.map((propKey, i) => (
          <SettingsItem key={i} metadata={buildPropMetadata(propKey)} />
        ))}
      </Accordion.Body>
    </Accordion.Item>
  )
}

export function SettingsItem (props: Props): JSX.Element | null {
  const { metadata } = props

  let item: JSX.Element | null = null
  switch (metadata.type) {
    case 'info':
      break

    case 'checkbox':
      item = <SettingsCheckbox metadata={metadata} />
      break

    case 'input':
      item = <SettingsInput metadata={metadata} />
      break

    case 'number':
      item = <SettingsNumber metadata={metadata} />
      break

    case 'array':
      item = <ArraySettingsItem metadata={metadata} />
      break

    case 'object':
      item = <ObjectSettingsItem metadata={metadata} />
      break
  }

  return (
    <>
      {item}
      <SettingsDescription metadata={metadata} />
    </>
  )
}
