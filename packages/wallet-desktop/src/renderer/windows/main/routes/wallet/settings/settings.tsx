import * as React from 'react'

import { Bootstrap, Extendible, HorizontalAccordion, ListSelector, Resizeable, Section } from '@wallet/renderer/components'
import { cloudVaultMetadata, developerMetadata, walletMetadata, walletProtocolMetadata } from './metadatas'
import { SettingsItem } from './settings-item'
import { MetadataRecord } from './settings-metadata'

import './settings.scss'
import { Form } from 'react-bootstrap'

export function Settings (): JSX.Element {
  const settingsMetadatas: MetadataRecord = {
    ...developerMetadata,
    ...walletProtocolMetadata,
    ...walletMetadata,
    ...cloudVaultMetadata
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
        <Bootstrap>
          {settingsGroup !== undefined ? (
            <Section title={settingsGroup}>
              <Form>
                <div className='settings-items'>
                  {settingsMetadatas[settingsGroup].map((metadata, i) => (
                    <SettingsItem key={i} metadata={metadata} />
                  ))}
                </div>
              </Form>
            </Section>
          ) : null}
        </Bootstrap>
      </Extendible>
    </HorizontalAccordion>
  )
}
