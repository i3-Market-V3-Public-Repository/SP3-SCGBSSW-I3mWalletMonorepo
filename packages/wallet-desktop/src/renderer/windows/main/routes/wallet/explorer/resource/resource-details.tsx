import { Resource } from '@i3m/base-wallet'
import { Extendible, Section } from '@wallet/renderer/components'
import { VerifiableCredentialDetails } from './verifiable-credential-details'

interface Props {
  resource: Resource
}

function ResourceSelector (props: Props): JSX.Element | null {
  const { resource } = props

  switch (props.resource.type) {
    case 'VerifiableCredential':
      return <VerifiableCredentialDetails vc={resource} />

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
