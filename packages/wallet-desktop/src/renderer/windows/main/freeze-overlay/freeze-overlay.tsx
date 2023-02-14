import Loader from 'react-spinners/ClipLoader'

import { WalletTask } from '@wallet/lib'
import { useSharedMemory } from '@wallet/renderer/communication'

import './freeze-overlay.scss'

const COLOR = '#3BBD59'

export function FreezeOverlay (): JSX.Element | null {
  const [sharedMemory] = useSharedMemory()

  let task: WalletTask | undefined = sharedMemory.tasks
    .filter((task) => task.description.freezing === true)[0]

  return task !== undefined ? (
    <div className='freeze-overlay'>
      <div className='overlay' style={{color: COLOR}}>
        <Loader color={COLOR} />
        <span className='title'>{task.description.details}...</span>
      </div>
    </div>
  ) : null
}
