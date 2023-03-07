import * as React from 'react'

import { Identity, VerifiableCredentialResource } from '@i3m/base-wallet'
import { useSharedMemory } from '@wallet/renderer/communication'
import { Details, JsonUi } from '@wallet/renderer/components'
import { getClaims } from '@wallet/renderer/util'

interface Props {
  vc: VerifiableCredentialResource
}

export function VerifiableCredentialDetails (props: Props): JSX.Element {
  const { vc } = props
  const [sharedMemory] = useSharedMemory()

  let identity: Identity | undefined
  if (vc.identity !== undefined) {
    identity = sharedMemory.identities[vc.identity]
  }
  const alias = identity?.alias

  return (
    <>
      <Details.Body>
        <Details.Title>Summary</Details.Title>
        <Details.Grid>
          <Details.Input label='ID' value={vc.id} />
          <Details.Input label='Type' value='Verifiable Credential' />
          {alias !== undefined
            ? (
              <Details.Input label='From identity' value={alias} />
            ) : null}
          <Details.Input label='Issuance date' value={vc.resource.issuanceDate.toString()} />
        </Details.Grid>
      </Details.Body>
      <Details.Body>
        <Details.Title>Content</Details.Title>
        <JsonUi
          prop='Claims'
          value={getClaims(vc.resource)}
        />
        <JsonUi
          prop='Data'
          value={vc.resource}
        />
      </Details.Body>
    </>
  )
}
