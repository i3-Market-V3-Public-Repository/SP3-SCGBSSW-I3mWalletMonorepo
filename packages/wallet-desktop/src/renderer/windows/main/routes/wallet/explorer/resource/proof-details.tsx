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
  let proofType = 'Unknown'
  let iatDate = ''
  try {
    proofPayload = decodeJwt(resource.resource) as unknown as NrProofPayload
    proofType = proofPayload.proofType
    iatDate = (new Date(proofPayload.iat * 1000)).toString()
  } catch {
    // TODO: Cannot use dispach action because it refereshes this component and creates an infinite loop
    // dispatch(showToastAction.create({
    //   message: 'Invalid resource',
    //   details: `Cannot verify the resource ${name}`,
    //   type: 'error'
    // }))
  }

  let verificationPublicJwk: string | undefined

  let proofTypeExpanded = ''
  if (resource.parentResource !== undefined) {
    const dea = sharedMemory.resources[resource.parentResource] as DataExchangeResource
    switch (proofType) {
      case 'PoO':
        verificationPublicJwk = dea.resource.orig
        proofTypeExpanded = 'Proof of Origin (PoO)'
        break
      case 'PoR':
        verificationPublicJwk = dea.resource.dest
        proofTypeExpanded = 'Proof of Reception (PoR)'
        break
      case 'PoP':
        verificationPublicJwk = dea.resource.orig
        proofTypeExpanded = 'Proof of Publication (PoP)'
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
          <Details.Input label='Proof type' value={proofTypeExpanded} />
          <Details.Input label='Issued at' value={iatDate} />
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
