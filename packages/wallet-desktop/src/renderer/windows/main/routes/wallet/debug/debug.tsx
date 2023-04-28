import * as React from 'react'

import { useSharedMemory } from '@wallet/renderer/communication'
import { Details, JsonUi, Section } from '@wallet/renderer/components'
import { usePresistentState } from '@wallet/renderer/hooks'
import { AccordionProps } from 'react-bootstrap'

type AccordionActiveKeys = Record<string, string[] | undefined>

export function Debug (): JSX.Element {
  const [sharedMemory] = useSharedMemory()
  const [accordionActiveKeys, setAccordionActiveKeys] = usePresistentState<AccordionActiveKeys>('debug.accordions', {})

  const buildActiveKeys = (name: string): AccordionProps => ({
    activeKey: accordionActiveKeys[name] ?? [],
    onSelect (value) {
      if (value instanceof Array) {
        setAccordionActiveKeys({
          ...accordionActiveKeys,
          [name]: value
        })
      }
    }
  })

  return (
    <Section className='debug' title='Debug' scroll light center>
      <Details>
        <Details.Body>
          <Details.Title>Settings</Details.Title>
          <JsonUi prop='Public settings' value={sharedMemory.settings.public} {...buildActiveKeys('publicSettings')} />
          <JsonUi prop='Private settings' value={sharedMemory.settings.private} {...buildActiveKeys('privateSettings')} />
        </Details.Body>
        <Details.Body>
          <Details.Title>Wallet</Details.Title>
          <JsonUi prop='Resources' value={sharedMemory.resources} {...buildActiveKeys('resources')} />
          <JsonUi prop='Identities' value={sharedMemory.identities} {...buildActiveKeys('identities')} />
          <JsonUi prop='Wallets metadata' value={sharedMemory.walletsMetadata} {...buildActiveKeys('walletMetadatas')} />
          <JsonUi prop='Default providers' value={sharedMemory.defaultProviders} {...buildActiveKeys('DefaultProviders')} />
        </Details.Body>
        <Details.Body>
          <Details.Title>Communications</Details.Title>
          <JsonUi prop='Cloud Vault' value={sharedMemory.cloudVaultData} {...buildActiveKeys('cloudVault')} />
          <JsonUi prop='Connect' value={sharedMemory.connectData} {...buildActiveKeys('connect')} />
        </Details.Body>
        <Details.Body>
          <Details.Title>UI</Details.Title>
          <JsonUi prop='Toasts' value={sharedMemory.toasts} {...buildActiveKeys('toasts')} />
          <JsonUi prop='Dialogs' value={sharedMemory.dialogs} {...buildActiveKeys('dialogs')} />
          <JsonUi prop='Tasks' value={sharedMemory.tasks} {...buildActiveKeys('tasks')} />
        </Details.Body>
      </Details>
    </Section>
  )
}
