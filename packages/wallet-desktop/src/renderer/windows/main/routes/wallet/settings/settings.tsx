import { HorizontalAccordion, Fixed, Extendible, Section, ListSelector } from '@wallet/renderer/components'
import { SettingsItem } from './settings-item'
import { SettingsMetadata } from './settings-metadata'

import './settings.scss'

export function Settings (): JSX.Element {
  const settingsMetadatas: Record<string, SettingsMetadata[]> = {
    Developer: [
      {
        label: 'Developer Functions',
        type: 'checkbox',
        key: 'developer.enableDeveloperFunctions'
      },
      {
        label: 'Developer API',
        type: 'checkbox',
        key: 'developer.enableDeveloperApi'
      }
    ]
  }
  const groups = Object.keys(settingsMetadatas)
  const [settingsGroup, setSettingsGroup] = React.useState<string>(groups[0])

  return (
    <HorizontalAccordion className='settings'>
      <Fixed className='settings-list'>
        <Section title='Settings'>
          <ListSelector selected={settingsGroup} items={groups} onSelect={setSettingsGroup} />
        </Section>
      </Fixed>
      <Extendible className='settings-group'>
        {settingsGroup !== undefined ? (
          <Section title={settingsGroup}>
            {settingsMetadatas[settingsGroup].map((metadata, i) => (
              <SettingsItem key={i} metadata={metadata} />
            ))}
          </Section>
        ) : null}
      </Extendible>
    </HorizontalAccordion>
  )
}
