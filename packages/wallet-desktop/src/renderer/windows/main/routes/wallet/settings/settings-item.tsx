import { SettingsMetadata } from './settings-metadata'
import { SettingsCheckbox } from './settings-checkbox'
import { SettingsInput } from './settings-input'
import { SettingsNumber } from './settings-number'

interface Props {
  metadata: SettingsMetadata
}

export function SettingsItem (props: Props): JSX.Element | null {
  const { metadata } = props
  switch (metadata.type) {
    case 'checkbox':
      return <SettingsCheckbox metadata={metadata} />
    case 'input':
      return <SettingsInput metadata={metadata} />
    case 'number':
      return <SettingsNumber metadata={metadata} />
    default:
      return null
  }
}
