import { logoutCloudAction, stopCloudSyncAction } from '@wallet/lib'
import { useAction } from '@wallet/renderer/communication'

export function Authenticated (): JSX.Element {
  const dispatch = useAction()

  const onLogout = (): void => {
    dispatch(logoutCloudAction.create())
  }

  const onDelete = (): void => {
    dispatch(stopCloudSyncAction.create())
  }

  return (
    <>
      <div className='authenticated'>
        You are already authenticated
      </div>
      <div className='authenticated'>
        You are connected to the vault __URL__
      </div>
      <div className='authenticated'>
        With the username __USER__
      </div>
      <button onClick={onDelete}>Delete cloud storage</button>
      <button onClick={onLogout}>Logout</button>
    </>
  )
}
