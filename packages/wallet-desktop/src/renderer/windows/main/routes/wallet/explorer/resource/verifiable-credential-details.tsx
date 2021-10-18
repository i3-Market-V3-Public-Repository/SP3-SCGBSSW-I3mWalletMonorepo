import { Identity, Resource } from '@i3-market/base-wallet'
import { useSharedMemory } from '@wallet/renderer/communication'

interface Props {
  vc: Resource & { type: 'VerifiableCredential' }
}

export function VerifiableCredentialDetails (props: Props): JSX.Element {
  const { vc } = props

  const [sharedMemory] = useSharedMemory()

  let identity: Identity | undefined
  if (vc.identity !== undefined) {
    identity = sharedMemory.identities[vc.identity]
  }

  return (
    <div className='details-body'>
      <div className='details-param inline'>
        <span>Id:</span>
        <input type='text' disabled value={vc.id} />
      </div>
      <div className='details-param inline'>
        <span>Type:</span>
        <input type='text' disabled value='Verifiable Credential' />
      </div>
      {identity !== undefined
        ? (
          <div className='details-param inline'>
            <span>From identity:</span>
            <input type='text' disabled value={identity.alias} />
          </div>
        ) : null}
      <div className='details-param'>
        <span>Issuer:</span>
        <input type='text' disabled value={vc.resource.issuer.id} />
      </div>
      <div className='details-param'>
        <span>Issuance date:</span>
        <input type='text' disabled value={vc.resource.issuanceDate.toString()} />
      </div>
      {Object.keys(vc.resource.credentialSubject)
        .filter((claimType) => claimType !== 'id')
        .map((claimType, i) => {
          return (
            <div key={i} className='details-param inline'>
              <span>Claim "{claimType}":</span>
              <input type='text' disabled value={vc.resource.credentialSubject[claimType]} />
            </div>
          )
        })}
    </div>
  )
}
