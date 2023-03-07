import * as React from 'react'

import { ListSelector, Resizeable, Section } from '@wallet/renderer/components'
import { cloudVaultMetadata, developerMetadata, walletMetadata, walletProtocolMetadata } from './metadatas'
import { SettingsItem } from './settings-item'
import { MetadataRecord } from './settings-metadata'

import { Form } from 'react-bootstrap'
import './settings.scss'

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
  const onSubmit: React.FormEventHandler<HTMLFormElement> = (ev) => {
    ev.preventDefault()
  }

  return (
    <Resizeable className='settings'>
      <Resizeable.Dynamic className='settings-list' stateId='wallet.settings.tree-list' resizeWidth>
        <Section title='Settings' scroll>
          <ListSelector selected={settingsGroup} items={groups} onSelect={setSettingsGroup} />
        </Section>
      </Resizeable.Dynamic>
      <Resizeable.Fixed className='settings-editor'>
        {settingsGroup !== undefined ? (
          <Section title={settingsGroup} scroll light>
            <Form className='settings-form' onSubmit={onSubmit}>
              <div className='settings-items'>
                {settingsMetadatas[settingsGroup].map((metadata, i) => (
                  <SettingsItem key={i} metadata={metadata} />
                ))}
              </div>
            </Form>
          </Section>
        ) : null}
      </Resizeable.Fixed>
    </Resizeable>
  )
}
