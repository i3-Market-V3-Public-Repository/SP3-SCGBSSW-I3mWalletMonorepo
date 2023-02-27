import _ from 'lodash'
import { useAction, useSharedMemory } from '@wallet/renderer/communication'

import { InputSettingsMetadata } from '../settings-metadata'

interface Props {
  metadata: InputSettingsMetadata
}

export function SettingsInput (props: Props): JSX.Element {
  const { metadata } = props

  const dispatch = useAction()
  const [sharedMemory, setSharedMemory] = useSharedMemory()
  const value = _.get(sharedMemory.settings, metadata.key)

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
    <div className='settings-input'>
      <label>{metadata.label}</label>
      <input type='text' placeholder={metadata.placeholder} onChange={onChange} value={value} />
    </div>
  )
}
