import _ from 'lodash'
import { useSharedMemory } from '@wallet/renderer/communication'
import { CheckboxSettingsMetadata } from './settings-metadata'

interface Props {
  metadata: CheckboxSettingsMetadata
}

export function SettingsCheckbox (props: Props): JSX.Element {
  const { metadata } = props
  const [sharedMemory, setSharedMemory] = useSharedMemory()
  const value = _.get(sharedMemory.settings, metadata.key)

  const onChange: React.ChangeEventHandler<HTMLInputElement> = (ev) => {
    const newSettings: any = {}
    _.set(newSettings, metadata.key, ev.target.checked)
    setSharedMemory({
      settings: newSettings
    })
  }

  return (
    <div className='settings-item settings-checkbox'>
      <label>
        {metadata.label}
        <input type='checkbox' onChange={onChange} checked={value} />
      </label>
    </div>
  )
}
