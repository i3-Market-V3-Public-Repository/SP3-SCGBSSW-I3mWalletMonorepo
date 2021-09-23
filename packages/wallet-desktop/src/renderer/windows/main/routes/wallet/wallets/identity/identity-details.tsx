import { Identity, Resource } from '@i3-market/base-wallet'
import { useSharedMemory } from '@wallet/renderer/communication'
import { Extendible, Section } from '@wallet/renderer/components'

import { IdentityResource } from './identity-resource'

interface Props {
  identity: Identity
}

export function IdentityDetails (props: Props): JSX.Element {
  const { identity } = props
  const [sharedMemory] = useSharedMemory()
  const resources = Object.keys(sharedMemory.resources)
    .map(id => sharedMemory.resources[id] as Resource)
    .filter((resource) => {
      return resource.identity === identity.did
    })

  return (
    <Extendible className='details'>
      <Section title='Details'>

        <div className='details-body'>
          <div className='details-param inline'>
            <span>Name:</span>
            <input type='text' disabled value={identity.alias} />
          </div>
          <div className='details-param'>
            <span>Description:</span>
            <input type='text' disabled value='' />
          </div>
          <div className='details-param'>
            <span>Associated DID:</span>
            <input type='text' disabled value={identity.did} />
          </div>
          <div className='details-param'>
            <span>Resources:</span>
            {resources.length === 0 ? <span>This identity has no resources associated</span> : (
              <div className='resources'>
                {resources.map((resource, i) => (
                  <IdentityResource resource={resource} key={i} />
                ))}
              </div>
            )}
          </div>
        </div>
        <div className='details-buttons' style={{ display: 'none' }}>
          <button>Obtain DDO</button>
        </div>
      </Section>
    </Extendible>
  )
}
