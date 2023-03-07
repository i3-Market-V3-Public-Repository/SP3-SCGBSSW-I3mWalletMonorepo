import * as React from 'react'

import { ContractResource, NonRepudiationProofResource, ObjectResource, Resource, VerifiableCredentialResource } from '@i3m/base-wallet'
import { ContractDetails } from './contract-details'
import { ObjectDetails } from './object-details'
import { ProofDetails } from './proof-details'
import { VerifiableCredentialDetails } from './verifiable-credential-details'
import { getResourceName } from '@wallet/renderer/util'
import { Details, Section } from '@wallet/renderer/components'

interface Props {
  resource: Resource
}

export function ResourceDetails (props: Props): JSX.Element {
  const { resource } = props
  const name = getResourceName(props.resource)

  let child: JSX.Element
  switch (props.resource.type) {
    case 'VerifiableCredential':
      child = <VerifiableCredentialDetails vc={resource as VerifiableCredentialResource} />
      break

    case 'Contract':
      child = <ContractDetails resource={resource as ContractResource} />
      break

    case 'NonRepudiationProof':
      child = <ProofDetails resource={resource as NonRepudiationProofResource} />
      break

    default:
      child = <ObjectDetails resource={resource as ObjectResource} />
      break
  }

  return (
    <Section title={name} scroll light>
      <Details>
        {child}
      </Details>
    </Section>
  )
}
