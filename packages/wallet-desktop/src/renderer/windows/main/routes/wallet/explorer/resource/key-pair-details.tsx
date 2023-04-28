import * as React from 'react'

import { Identity, KeyPairResource } from '@i3m/base-wallet'
import { useSharedMemory } from '@wallet/renderer/communication'
import { Details, JsonUi } from '@wallet/renderer/components'
import { getResourceName } from '@wallet/renderer/util'

interface Props {
  resource: KeyPairResource
}

export function KeyPairDetails (props: Props): JSX.Element {
  const { resource } = props

  const [sharedMemory] = useSharedMemory()

  let identity: Identity | undefined
  if (resource.identity !== undefined) {
    identity = sharedMemory.identities[resource.identity]
  }
  const name = getResourceName(props.resource)
  const identityAlias = identity?.alias

  return (
    <>
      <Details.Body>
        <Details.Title>Summary</Details.Title>
        <Details.Grid>
          <Details.Input label='Id' value={resource.id} />
          <Details.Input label='Name' value={name} />
          <Details.Input label='Type' value={resource.type} />
          {identityAlias !== undefined
            ? (
              <Details.Input label='From identity' value={identityAlias} />
            ) : null}
        </Details.Grid>
      </Details.Body>
      <Details.Body>
        <Details.Title>Content</Details.Title>
        <JsonUi prop='Key Pair' value={{ ...resource.resource.keyPair, privateJwk: undefined }} />
      </Details.Body>
    </>
  )
}
