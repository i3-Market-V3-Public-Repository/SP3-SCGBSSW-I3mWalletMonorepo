import { Identity, ContractResource } from '@i3m/base-wallet'
import { useSharedMemory } from '@wallet/renderer/communication'

interface Props {
  resource: ContractResource
}

export function ContractDetails (props: Props): JSX.Element {
  const { resource } = props

  const [sharedMemory] = useSharedMemory()

  let identity: Identity | undefined
  if (resource.identity !== undefined) {
    identity = sharedMemory.identities[resource.identity]
  }

  return (
    <div className='details-body'>
      {resource.name !== undefined
        ? (
          <div className='details-param inline'>
            <span>Name:</span>
            <input type='text' disabled value={resource.name} />
          </div>
        ) : null}
      <div className='details-param inline'>
        <span>Id:</span>
        <input type='text' disabled value={resource.id} />
      </div>
      <div className='details-param inline'>
        <span>Type:</span>
        <input type='text' disabled value='Contract' />
      </div>
      {identity !== undefined
        ? (
          <div className='details-param inline'>
            <span>From identity:</span>
            <input type='text' disabled value={identity.alias} />
          </div>
        ) : null}
      <div className='details-param expand'>
        <span>Data:</span>
        <textarea disabled value={JSON.stringify(resource.resource, null, 2)} />
      </div>
    </div>
  )
}
