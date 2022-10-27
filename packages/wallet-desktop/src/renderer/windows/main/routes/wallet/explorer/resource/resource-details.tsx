import { ContractResource, NonRepudiationProofResource, ObjectResource, Resource, VerifiableCredentialResource } from '@i3m/base-wallet'
import { Extendible, Section } from '@wallet/renderer/components'
import { ObjectDetails } from './object-details'
import { ContractDetails } from './contract-details'
import { VerifiableCredentialDetails } from './verifiable-credential-details'
import { NonRepudiationProofDetails } from './non-repudiation-proof-details'

interface Props {
  resource: Resource
}

function ResourceSelector (props: Props): JSX.Element | null {
  const { resource } = props

  switch (props.resource.type) {
    case 'VerifiableCredential':
      return <VerifiableCredentialDetails vc={resource as VerifiableCredentialResource} />

    case 'Object':
      return <ObjectDetails resource={resource as ObjectResource} />

    case 'Contract':
      return <ContractDetails resource={resource as ContractResource} />

    case 'NonRepudiationProof':
      return <NonRepudiationProofDetails resource={resource as NonRepudiationProofResource} />

    default:
      return <div>Unknown resource type</div>
  }
}

export function ResourceDetails (props: Props): JSX.Element {
  return (
    <Extendible className='details'>
      <Section title='Details'>
        <ResourceSelector {...props} />
      </Section>
    </Extendible>
  )
}
