import _ from 'lodash'
import { useSharedMemory } from '@wallet/renderer/communication'
import { SettingsMetadata } from './settings-metadata'

interface Props {
  metadata: SettingsMetadata
}

export function SettingsDescription (props: Props): JSX.Element | null {
  const { metadata } = props
  if (metadata.description === undefined) {
    return null
  }

  const { description } = metadata
  const [sharedMemory] = useSharedMemory()
  const value = _.get(sharedMemory.settings, metadata.key)

  let visible: boolean | undefined
  if (description.visible instanceof Function) {
    visible = description.visible(metadata, value as never)
  } else {
    visible = description.visible
  }
  if (visible === false) {
    return null
  }

  let message: JSX.Element
  if (description.message instanceof Function) {
    message = description.message(metadata, value as never)
  } else {
    message = description.message
  }

  return (
    <div className='settings-description'>
      {message}
    </div>
  )
}
