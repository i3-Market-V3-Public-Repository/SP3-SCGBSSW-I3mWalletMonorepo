import { CurrentWallet } from './items'

import './status-bar.scss'

export function StatusBar (): JSX.Element {
  return (
    <div className='status-bar'>
      <CurrentWallet />
    </div>
  )
}
