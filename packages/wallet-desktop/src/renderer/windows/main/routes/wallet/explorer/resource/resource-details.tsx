import * as React from 'react'

import { ContractResource, DataExchangeResource, KeyPairResource, NonRepudiationProofResource, ObjectResource, Resource, VerifiableCredentialResource } from '@i3m/base-wallet'
import { ContractDetails } from './contract-details'
import { ObjectDetails } from './object-details'
import { ProofDetails } from './proof-details'
import { VerifiableCredentialDetails } from './verifiable-credential-details'
import { getResourceName } from '@wallet/renderer/util'
import { Details, Section, SectionProps } from '@wallet/renderer/components'
import { DataExchangeDetails } from './data-eschange-details'
import { KeyPairDetails } from './key-pair-details'

interface Props extends SectionProps {
  item: Resource
}

export function ResourceDetails (props: Props): JSX.Element {
  const { item: resource, title, ...sectionProps } = props
  const name = getResourceName(props.item)

  let child: JSX.Element
  switch (props.item.type) {
    case 'VerifiableCredential':
      child = <VerifiableCredentialDetails vc={resource as VerifiableCredentialResource} />
      break

    case 'Contract':
      child = <ContractDetails resource={resource as ContractResource} />
      break

    case 'DataExchange':
      child = <DataExchangeDetails resource={resource as DataExchangeResource} />
      break

    case 'KeyPair':
      child = <KeyPairDetails resource={resource as KeyPairResource} />
      break

    case 'NonRepudiationProof':
      child = <ProofDetails resource={resource as NonRepudiationProofResource} />
      break

    default:
      child = <ObjectDetails resource={resource as ObjectResource} />
      break
  }

  return (
    <Section title={name} {...sectionProps}>
      <Details>
        {child}
      </Details>
    </Section>
  )
}
