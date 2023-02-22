import { faBarsProgress } from '@fortawesome/free-solid-svg-icons'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import Loader from 'react-spinners/ClipLoader'

import { useSharedMemory } from '@wallet/renderer/communication'
import { StatusBarItem } from './status-bar-item'

export function TaskManager (): JSX.Element | null {
  const [sharedMemory] = useSharedMemory()

  const tasks = sharedMemory.tasks.filter(task => task.description.freezing !== true)

  let title: string
  let icon: JSX.Element
  if (tasks.length === 1) {
    title = `${tasks[0].description.title}...`
  } else if (tasks.length > 1) {
    title = `${tasks.length} tasks pending...`
  } else {
    title = 'No tasks'
  }

  if (tasks.length > 0) {
    icon = <Loader className='loader' color='white' />
  } else {
    icon = <FontAwesomeIcon icon={faBarsProgress} className='icon' />
  }

  return (
    <StatusBarItem>
      {icon}
      <span>{title}</span>
    </StatusBarItem>
  )
}
