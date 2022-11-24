import _ from 'lodash'
import { useAction, useSharedMemory } from '@wallet/renderer/communication'
import { NumberSettingsMetadata } from '../settings-metadata'

interface Props {
  metadata: NumberSettingsMetadata
}

export function SettingsNumber (props: Props): JSX.Element {
  const { metadata } = props

  const dispatch = useAction()
  const [sharedMemory, setSharedMemory] = useSharedMemory()
  const value = _.get(sharedMemory.settings, metadata.key)

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
    <div className='settings-number'>
      <label>{metadata.label}</label>
      <input type='number' onChange={onChange} value={value} />
    </div>
  )
}
