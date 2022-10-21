import { Resource } from '@i3m/base-wallet'

interface Props {
  resource: Resource
}

export function IdentityResource (props: Props): JSX.Element {
  const { resource } = props
  const resourceProps: Map<string, string> = new Map()
  switch(resource.type) {
    case 'VerifiableCredential':
      resourceProps.set('Claims',
        Object.keys(resource.resource.credentialSubject)
          .filter(key => key !== 'id')
          .join(', '))
  }

  const copy: React.MouseEventHandler = async (ev) => {
    await navigator.clipboard.writeText(JSON.stringify(resource, undefined, 2))
  }

  return (
    <div className='resource'>
      <div className='resource-content'>
        <div className='identity-param inline'>
          <span>Type: {resource.type}</span>
        </div>
        { [...resourceProps.entries()].map(([key, value]) => (
          <div key={key} className='identity-param inline'>
            <span>{key}: </span>
            <input type='text' disabled value={value} />
          </div>
        ))}
        <button onClick={copy} style={{ display: 'none' }}>
          Extract
        </button>
      </div>
    </div>
  )
}
