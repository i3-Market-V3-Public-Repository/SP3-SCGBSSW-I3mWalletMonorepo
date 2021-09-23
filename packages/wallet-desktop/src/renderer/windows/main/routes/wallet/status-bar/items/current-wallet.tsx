import { faWallet } from '@fortawesome/free-solid-svg-icons'

import { selectWalletAction } from '@wallet/lib'
import { useSharedMemory, useAction } from '@wallet/renderer/communication'
import { StatusBarItem } from './status-bar-item'

export function CurrentWallet (): JSX.Element | null {
  const [sharedMemory] = useSharedMemory()
  const dispatch = useAction()

  const wallet = sharedMemory.settings.wallet

  const onClick = (): void => {
    dispatch(selectWalletAction.create())
  }

  return wallet.current !== undefined ? (
    <StatusBarItem icon={faWallet} onClick={onClick}>
      {wallet.current}
    </StatusBarItem>
  ) : null
}
