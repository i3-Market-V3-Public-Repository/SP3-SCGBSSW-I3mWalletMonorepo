import * as React from 'react'

import { Identity, NonRepudiationProofResource } from '@i3m/base-wallet'
import type { NrProofPayload } from '@i3m/non-repudiation-library'
import { useSharedMemory } from '@wallet/renderer/communication'
import { Details, JsonUi } from '@wallet/renderer/components'
import { getResourceName } from '@wallet/renderer/util'
import { decodeJwt } from 'jose'

interface Props {
  resource: NonRepudiationProofResource
}

export function ProofDetails (props: Props): JSX.Element {
  const { resource } = props
  const name = getResourceName(props.resource)
  const [sharedMemory] = useSharedMemory()
  // const dispatch = useAction()

  let proofPayload: NrProofPayload | undefined
  try {
    proofPayload = decodeJwt(resource.resource) as unknown as NrProofPayload
  } catch {
    // TODO: Cannot use dispach action because it refereshes this component and creates an infinite loop
    // dispatch(showToastAction.create({
    //   message: 'Invalid resource',
    //   details: `Cannot verify the resource ${name}`,
    //   type: 'error'
    // }))
  }
  const proofType = proofPayload?.proofType ?? 'Unknown'

  let identity: Identity | undefined
  if (resource.identity !== undefined) {
    identity = sharedMemory.identities[resource.identity]
  }
  const identityAlias = identity?.alias

  return (
    <>
      <Details.Body>
        <Details.Title>Summary</Details.Title>
        <Details.Grid>
          <Details.Input label='Id' value={resource.id} />
          <Details.Input label='Name' value={name} />
          <Details.Input label='Resource type' value={resource.type} />
          <Details.Input label='Proof type' value={proofType} />
          {identityAlias !== undefined
            ? (
              <Details.Input label='From identity' value={identityAlias} />
            ) : null}
        </Details.Grid>
      </Details.Body>
      <Details.Body>
        <Details.Title>Content</Details.Title>
        <JsonUi prop='Claims' value={proofPayload} />
        <JsonUi prop='JSON Web Signature' value={{ 'compact serialization': resource.resource }} />
      </Details.Body>
    </>
  )
}
