import * as React from 'react'

import _ from 'lodash'

import { useSharedMemory } from '@wallet/renderer/communication'

import { SharedMemory } from '@wallet/lib'
import { BaseMetadata, ItemMetadata } from './settings-metadata'

interface Props {
  metadata: ItemMetadata
}

function getValue<T> (metadata: BaseMetadata<T>, sharedMemory: SharedMemory): T {
  if (metadata === undefined) {
    return undefined as T
  }
  const key = (metadata as any).key as string
  if (key === undefined) {
    return undefined as T
  }
  return _.get(sharedMemory, `settings.${key}`) as T
}

export function SettingsDescription (props: Props): JSX.Element | null {
  const { metadata } = props
  if (metadata.description === undefined) {
    return null
  }

  const { description } = metadata
  const [sharedMemory] = useSharedMemory()
  const value = getValue(metadata, sharedMemory)

  let visible: boolean | undefined
  if (description.visible instanceof Function) {
    visible = description.visible(metadata, value)
  } else {
    visible = description.visible
  }
  if (visible === false) {
    return null
  }

  let message: JSX.Element
  if (description.message instanceof Function) {
    message = description.message(metadata, value)
  } else {
    message = description.message
  }

  const title = description.title

  return (
    <div className='settings-description'>
      {title !== undefined ? (
        <div className='settings-description-title'>
          <label>{title}</label>
        </div>
      ) : null}
      <div className='settings-description-message'>
        {message}
      </div>

    </div>
  )
}
