
import * as React from 'react'

import { DEFAULT_CLOUD_URL } from '@wallet/lib'
import { useSharedMemory } from '@wallet/renderer/communication'
import { Details, Section } from '@wallet/renderer/components'

import { Button } from 'react-bootstrap'
import './cloud-vault.scss'

export function CloudVault (): JSX.Element {
  const [mem] = useSharedMemory()
  const { cloudVaultData: publicCloudData } = mem
  const { cloud: privateCloudData } = mem.settings

  const status = publicCloudData.state
  const username = privateCloudData?.credentials?.username
  const url = privateCloudData?.url ?? DEFAULT_CLOUD_URL
  if (publicCloudData.state !== 'disconnected') {
    // status = 'Connected'
  } else if (privateCloudData?.credentials !== undefined) {
    // status = 'With credentials'
  } else {
    // status = 'Disconnected'
  }

  return (
    <Section className='cloud-vault' title='Cloud Vault' scroll light>
      <Details>
        <Details.Body>
          <Details.Title>Summary</Details.Title>
          <Details.Grid>
            <Details.Input label='Status' value={status} />
            {username !== undefined ? <Details.Input label='Username' value={username} /> : null}
            <Details.Input label='URL' value={url} />
          </Details.Grid>
        </Details.Body>
        <Details.Separator />
        <Details.Body>
          <Details.Grid>
            <Details.Buttons title='Cloud connection'>
              <Button>Login</Button>
              <Button>Register</Button>
              <Button variant='danger'>Logout</Button>
            </Details.Buttons>
            <Details.Buttons title='Cloud actions'>
              <Button>Force sync</Button>
              <Button variant='danger'>Delete cloud</Button>
            </Details.Buttons>
          </Details.Grid>
        </Details.Body>
      </Details>
    </Section>
  )
}
