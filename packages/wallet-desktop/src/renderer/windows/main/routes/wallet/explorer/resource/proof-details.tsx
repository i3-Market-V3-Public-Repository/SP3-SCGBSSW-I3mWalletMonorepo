import * as React from 'react'

import { DataExchangeResource, NonRepudiationProofResource } from '@i3m/base-wallet'
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

  let verificationPublicJwk: string | undefined

  if (resource.parentResource !== undefined) {
    const dea = sharedMemory.resources[resource.parentResource] as DataExchangeResource
    switch (proofType) {
      case 'PoO':
        verificationPublicJwk = dea.resource.orig
        break
      case 'PoR':
        verificationPublicJwk = dea.resource.dest
        break
      case 'PoP':
        verificationPublicJwk = dea.resource.orig
        break
      default:
        break
    }
  }

  return (
    <>
      <Details.Body>
        <Details.Title>Summary</Details.Title>
        <Details.Grid>
          <Details.Input label='Id' value={resource.id} />
          <Details.Input label='Name' value={name} />
          <Details.Input label='Resource type' value={resource.type} />
          <Details.Input label='Proof type' value={proofType} />
          {(verificationPublicJwk !== undefined) ? (
            <Details.Input label='Verification Public JWK' value={verificationPublicJwk} />
          ) : ''}
        </Details.Grid>
      </Details.Body>
      <Details.Body>
        <Details.Title>Content</Details.Title>
        <JsonUi prop='Claims' value={proofPayload} />
        <JsonUi
          prop='JSON Web Signature' value={{
            'compact serialization': resource.resource,
            'verification public JWK': verificationPublicJwk ?? undefined
          }}
        />
      </Details.Body>
    </>
  )
}
