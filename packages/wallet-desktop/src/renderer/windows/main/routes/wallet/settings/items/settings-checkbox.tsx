import _ from 'lodash'
import { useAction, useSharedMemory } from '@wallet/renderer/communication'
import { CheckboxSettingsMetadata } from '../settings-metadata'

interface Props {
  metadata: CheckboxSettingsMetadata
}

export function SettingsCheckbox (props: Props): JSX.Element {
  const { metadata } = props

  const dispatch = useAction()
  const [sharedMemory, setSharedMemory] = useSharedMemory()
  const value = _.get(sharedMemory.settings, metadata.key)

  const onChange: React.ChangeEventHandler<HTMLInputElement> = (ev) => {
    const newValue = ev.target.checked
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
    <div className='settings-checkbox'>
      <label>
        {metadata.label}
        <input type='checkbox' onChange={onChange} checked={value} />
      </label>
    </div>
  )
}
