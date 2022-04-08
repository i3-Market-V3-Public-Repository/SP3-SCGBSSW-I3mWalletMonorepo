import { Resource } from '@i3m/base-wallet'
import { Extendible, Section } from '@wallet/renderer/components'
import { VerifiableCredentialDetails } from './verifiable-credential-details'

interface Props {
  resource: Resource
}

export function ResourceDetails (props: Props): JSX.Element {
  const { resource } = props

  return (
    <Extendible className='details'>
      <Section title='Details'>
        {resource.type === 'VerifiableCredential'
          ? <VerifiableCredentialDetails vc={resource} />
          : <div>Unknown resource type</div>}
      </Section>
    </Extendible>
  )
}
