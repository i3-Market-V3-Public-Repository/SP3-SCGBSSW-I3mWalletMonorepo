import { startCase } from 'lodash'
import * as React from 'react'

import { DataExchangeResource, KeyPairResource } from '@i3m/base-wallet'
import { useSharedMemory } from '@wallet/renderer/communication'
import { Details, JsonUi } from '@wallet/renderer/components'
import { getResourceName, getResourceParent } from '@wallet/renderer/util'

interface Props {
  resource: DataExchangeResource
}

export function DataExchangeDetails (props: Props): JSX.Element {
  const { resource } = props
  const [sharedMemory] = useSharedMemory()
  const name = getResourceName(props.resource)

  let identity: string | undefined
  let role: string | undefined
  const keyPair = getResourceParent<KeyPairResource>(sharedMemory, resource, { type: 'KeyPair' })
  if (keyPair != null) {
    identity = getResourceName(keyPair)
    const publicJwk = keyPair?.resource.keyPair?.publicJwk
    role = (publicJwk === resource.resource.orig) ? 'provider' : 'consumer'
  }

  return (
    <>
      <Details.Body>
        <Details.Title>Summary</Details.Title>
        <Details.Grid>
          <Details.Input label='Id' value={resource.id} />
          <Details.Input label='Name' value={name} />
          <Details.Input label='Type' value={resource.type} />
          {(identity !== undefined) ? (
            <Details.Input label='Identity' value={identity} />
          ) : ''}
          {(role !== undefined) ? (
            <Details.Input label='Role' value={role} />
          ) : ''}
        </Details.Grid>
      </Details.Body>
      <Details.Body>
        <Details.Title>Content</Details.Title>
        <JsonUi prop={startCase(resource.type)} value={resource.resource} />
      </Details.Body>
    </>
  )
}
