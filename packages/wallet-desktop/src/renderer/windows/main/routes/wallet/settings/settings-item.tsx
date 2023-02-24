import _ from 'lodash'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import { faTrash, faPlus } from '@fortawesome/free-solid-svg-icons'

import { useAction, useSharedMemory } from '@wallet/renderer/communication'

import { ArraySettingsMetadata, ItemMetadata, ObjectSettingsMetadata, SettingsMetadata } from './settings-metadata'
import { SettingsCheckbox, SettingsInput, SettingsNumber } from './items'
import { SettingsDescription } from './settings-description'

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
  const value = _.get(sharedMemory.settings, metadata.key) as any[]

  const onAddClick: React.MouseEventHandler = (ev) => {
    const newSettings: any = {}
    _.set(newSettings, metadata.key, [
      ...value,
      metadata.defaults(metadata, value)
    ])

    setSharedMemory({
      settings: newSettings
    })
  }

  const onDeleteClick = (i: number): React.MouseEventHandler => (ev) => {
    if (metadata.canDelete !== undefined && !metadata.canDelete(i, value[i], sharedMemory, dispatch)) {
      // Errors should be shown using dispatch inside canDelete method!
      return
    }

    const newSettings: any = {}
    value.splice(i, 1)
    _.set(newSettings, metadata.key, [...value])
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
    <div className='settings-item settings-array'>
      <label>{metadata.label}</label>
      {value.map((item, i) => (
        <div className='settings-array-item' key={i}>
          <FontAwesomeIcon className='settings-array-button' icon={faTrash} onClick={onDeleteClick(i)} />
          <SettingsItem metadata={buildChildMetadata(i)} />
        </div>
      ))}
      <FontAwesomeIcon className='settings-array-button' icon={faPlus} onClick={onAddClick} />
    </div>
  )
}

function ObjectSettingsItem (props: ObjectProps): JSX.Element {
  const { metadata } = props

  const properties = Object
    .keys(metadata.innerType)
    .sort((a, b) => a > b ? 1 : b > a ? -1 : 0)

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
    <div className='settings-item settings-object'>
      <label>{metadata.label}</label>
      {properties.map((propKey, i) => (
        <div key={i} className='settings-object-properties'>
          <SettingsItem metadata={buildPropMetadata(propKey)} />
        </div>
      ))}
    </div>
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
    <div className='settings-item'>
      {item}
      <SettingsDescription metadata={metadata} />
    </div>
  )
}
