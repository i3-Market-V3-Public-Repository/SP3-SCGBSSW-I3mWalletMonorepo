import { InputSettingsMetadata } from './settings-metadata'

interface Props {
  metadata: InputSettingsMetadata
}

export function SettingsInput (props: Props): JSX.Element {
  const { metadata } = props

  return (
    <div className='settings-item settings-input'>
      <label>{metadata.label}</label>
      <input type='text' />
    </div>
  )
}
