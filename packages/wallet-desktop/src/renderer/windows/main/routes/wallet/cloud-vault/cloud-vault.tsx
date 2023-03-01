
import * as React from 'react'

import { useSharedMemory } from '@wallet/renderer/communication'
import { Bootstrap, HorizontalAccordion } from '@wallet/renderer/components'
import { Authenticate } from './authenticate'
import { Authenticated } from './authenticated'

import './cloud-vault.scss'

export function CloudVault (): JSX.Element {
  const [mem] = useSharedMemory()
  const { state } = mem.cloudVaultData

  return (
    <HorizontalAccordion className='cloud-vault'>
      <Bootstrap>
        <div className='center-vertically'>
          {state === 'disconnected' ? <Authenticate /> : <Authenticated />}
        </div>
      </Bootstrap>
    </HorizontalAccordion>
  )
}
