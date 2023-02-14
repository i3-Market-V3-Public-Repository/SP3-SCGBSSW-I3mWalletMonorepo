import { CloudVault, CurrentWallet, Pairing, TaskManager } from './items'

import './status-bar.scss'

export function StatusBar (): JSX.Element {
  return (
    <div className='status-bar'>
      <CurrentWallet />
      <Pairing/>
      <CloudVault/>

      <div style={{ flex: 1 }}/>

      <TaskManager/>
    </div>
  )
}
