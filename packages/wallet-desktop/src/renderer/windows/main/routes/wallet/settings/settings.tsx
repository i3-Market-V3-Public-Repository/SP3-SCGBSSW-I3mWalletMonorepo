import { HorizontalAccordion, Extendible, Section, ListSelector, Resizeable } from '@wallet/renderer/components'
import { developerMetadata, walletMetadata, walletProtocolMetadata } from './metadatas'
import { SettingsItem } from './settings-item'
import { MetadataRecord } from './settings-metadata'

import './settings.scss'

export function Settings (): JSX.Element {
  const settingsMetadatas: MetadataRecord = {
    ...developerMetadata,
    ...walletProtocolMetadata,
    ...walletMetadata
  }
  const groups = Object.keys(settingsMetadatas)
    // Sort setting groups alphabetically
    .sort((a, b) => a > b ? 1 : a < b ? -1 : 0)
  const [settingsGroup, setSettingsGroup] = React.useState<string>(groups[0])

  return (
    <HorizontalAccordion className='settings'>
      <Resizeable className='settings-list' stateId='wallet.settings.tree-list' resizeWidth>
        <Section title='Settings'>
          <ListSelector selected={settingsGroup} items={groups} onSelect={setSettingsGroup} />
        </Section>
      </Resizeable>
      <Extendible className='settings-group'>
        {settingsGroup !== undefined ? (
          <Section title={settingsGroup}>
            <div className='settings-items'>
              {settingsMetadatas[settingsGroup].map((metadata, i) => (
                <SettingsItem key={i} metadata={metadata} />
              ))}
            </div>
          </Section>
        ) : null}
      </Extendible>
    </HorizontalAccordion>
  )
}
