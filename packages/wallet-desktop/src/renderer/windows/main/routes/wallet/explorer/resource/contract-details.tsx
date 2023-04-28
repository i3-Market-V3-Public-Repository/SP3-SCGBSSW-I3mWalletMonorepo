import * as React from 'react'

import { ContractResource, KeyPairResource } from '@i3m/base-wallet'
import { useSharedMemory } from '@wallet/renderer/communication'
import { Details, JsonUi } from '@wallet/renderer/components'
import { getResourceName, getResourceParent } from '@wallet/renderer/util'

interface Props {
  resource: ContractResource
}

export function ContractDetails (props: Props): JSX.Element {
  const { resource } = props
  const [sharedMemory] = useSharedMemory()
  const name = getResourceName(props.resource)

  let identity: string | undefined
  let role: string | undefined
  let publicJwk: string | undefined

  const keyPair = getResourceParent<KeyPairResource>(sharedMemory, resource, { type: 'KeyPair' })
  if (keyPair != null) {
    identity = getResourceName(keyPair)
    publicJwk = keyPair?.resource.keyPair?.publicJwk
  }
  if (publicJwk === undefined) {
    publicJwk = resource.resource.keyPair?.publicJwk
  }
  if (publicJwk !== undefined) {
    role = (publicJwk === resource.resource.dataSharingAgreement.dataExchangeAgreement.orig) ? 'provider' : 'consumer'
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
        <JsonUi prop='Data Sharing Agreement' value={resource.resource.dataSharingAgreement} />
        <JsonUi prop='Key Pair' value={{ ...resource.resource.keyPair, privateJwk: undefined }} />
      </Details.Body>
    </>
  )
}
