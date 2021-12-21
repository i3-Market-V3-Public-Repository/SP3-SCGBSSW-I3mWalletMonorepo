import _ from 'lodash'
import { useSharedMemory } from '@wallet/renderer/communication'
import { NumberSettingsMetadata } from './settings-metadata'

interface Props {
  metadata: NumberSettingsMetadata
}

export function SettingsNumber (props: Props): JSX.Element {
  const { metadata } = props
  const [sharedMemory, setSharedMemory] = useSharedMemory()
  const value = _.get(sharedMemory.settings, metadata.key)

  const onChange: React.ChangeEventHandler<HTMLInputElement> = (ev) => {
    const newSettings: any = {}
    _.set(newSettings, metadata.key, ev.target.valueAsNumber)
    setSharedMemory({
      settings: newSettings
    })
  }

  return (
    <div className='settings-item settings-number'>
      <label>{metadata.label}</label>
      <input type='number' onChange={onChange} value={value} />
    </div>
  )
}
