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

// function SettingsArrayHeader (props: React.PropsWithChildren<{ eventKey: string, onDelete: () => void }>): JSX.Element {
//   const decoratedOnClick = useAccordionButton(props.eventKey)

//   return (
//     <div className='settings-array-header'>
//       <span className='settings-array-name' onClick={decoratedOnClick}>{props.children}</span>
//       <CloseButton onClick={props.onDelete} />
//     </div>
//   )
// }

function ArraySettingsItem (props: ArrayProps): JSX.Element {
  const { metadata } = props

  const [sharedMemory, setSharedMemory] = useSharedMemory()
  const dispatch = useAction()
  const _values = _.get(sharedMemory.settings, metadata.key) ?? [] as any[]
  const values = _values instanceof Array ? _values : [_values]
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
            <CloseButton className='settings-array-button delete-button' onClick={onDeleteClick(i)} />
            <SettingsItem metadata={buildChildMetadata(i)} />
          </div>
        ))}
      </Accordion>
    </div>
  )

  // return (
  //   <Accordion className='settings-item settings-array' flush alwaysOpen>
  //     <label>{executeFunctionOrValue(metadata.label, metadata, values, sharedMemory)}</label>
  //     {values.map((value, i) => ({
  //       value,
  //       metadata: buildChildMetadata(i)
  //     })).map(({ value, metadata }, i) => (
  //       <Accordion.Item className='settings-array-item' key={i} eventKey={i.toString()}>
  //         <SettingsArrayHeader eventKey={i.toString()} onDelete={onDeleteClick(i)}>
  //           {executeFunctionOrValue(metadata.label, metadata, value, sharedMemory)}
  //         </SettingsArrayHeader>
  //         <Accordion.Body>
  //           <SettingsItem metadata={metadata} />
  //         </Accordion.Body>
  //       </Accordion.Item>
  //     ))}
  //     <FontAwesomeIcon className='settings-array-button' icon={faPlus} onClick={onAddClick} />
  //   </Accordion>
  // )
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
      <Accordion.Header>
        {label}
      </Accordion.Header>
      <Accordion.Body>
        {properties.map((propKey, i) => (
          <div key={i} className='settings-object-properties'>
            <SettingsItem metadata={buildPropMetadata(propKey)} />
          </div>
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
    <div className='settings-item'>
      {item}
      <SettingsDescription metadata={metadata} />
    </div>
  )
}
