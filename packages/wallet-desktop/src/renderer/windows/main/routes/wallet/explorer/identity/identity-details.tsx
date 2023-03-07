import * as React from 'react'

import { Identity, Resource } from '@i3m/base-wallet'
import { useSharedMemory } from '@wallet/renderer/communication'
import { Details, JsonUi, Section } from '@wallet/renderer/components'

import { getClaims, getResourceName } from '@wallet/renderer/util'

interface Props {
  identity: Identity
}

function resourceSummary (prev: any, resource: Resource): any {
  const { type } = resource
  const summary: any = { type }
  switch (type) {
    case 'VerifiableCredential':
      summary.claims = getClaims(resource.resource)
      break
  }

  const name = getResourceName(resource)
  prev[name] = summary

  return prev
}

export function IdentityDetails (props: Props): JSX.Element {
  const { identity } = props
  const [sharedMemory] = useSharedMemory()
  const resources = Object.keys(sharedMemory.resources)
    .map(id => sharedMemory.resources[id] as Resource)
    .filter((resource) => {
      return resource.identity === identity.did
    })

  const address = ethers.utils.computeAddress(`0x${identity.keys[0].publicKeyHex}`)
  const alias = identity.alias ?? identity.did

  return (
    <Section title={alias} scroll light>
      <Details>
        <Details.Body>
          <Details.Title>Summary</Details.Title>
          <Details.Grid>
            <Details.Input label='Name' value={alias} />
            <Details.Input label='Associated DID' value={identity.did} />
            <Details.Input label='Ethereum address' value={address} />
          </Details.Grid>
        </Details.Body>
        <Details.Body>
          <Details.Title>Content</Details.Title>
          <JsonUi
            prop='Resources'
            value={resources.reduce(resourceSummary, {})}
          />
        </Details.Body>
      </Details>
    </Section>
  )
}
