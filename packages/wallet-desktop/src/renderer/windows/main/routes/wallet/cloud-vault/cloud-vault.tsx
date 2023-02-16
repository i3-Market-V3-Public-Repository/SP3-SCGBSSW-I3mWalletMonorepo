import { useSharedMemory } from '@wallet/renderer/communication'
import { HorizontalAccordion } from '@wallet/renderer/components'
import { Authenticate } from './authenticate'
import { Authenticated } from './authenticated'

import './cloud-vault.scss'

export function CloudVault (): JSX.Element {
  const [mem] = useSharedMemory()
  const cloud = mem.settings.cloud

  return (
    <HorizontalAccordion className='cloud-vault'>
      <div className='center-vertically'>
        {cloud === undefined ? <Authenticate /> : <Authenticated />}
      </div>
    </HorizontalAccordion>
  )
}
