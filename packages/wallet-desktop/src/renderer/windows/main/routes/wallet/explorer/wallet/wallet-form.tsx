import * as React from 'react'

import { v4 as uuid } from 'uuid'

import { WalletInfo } from '@wallet/lib'

interface Props {
  walletPackages: string[]
  onSubmit?: (wallet: WalletInfo) => void
}

export function WalletForm (props: Props): JSX.Element {
  const { walletPackages } = props
  const onSubmit = props.onSubmit ?? (() => {})

  const [name, setName] = React.useState('')
  const [packageName, setPackageName] = React.useState(walletPackages[0])

  return (
    <div className='wallet-form'>

      <input className='modern' placeholder='Name your wallet...' value={name} onChange={(ev) => setName(ev.target.value)} />
      <select className='modern' value={packageName} onChange={(ev) => setPackageName(ev.target.value)}>
        {walletPackages.map((packageName, i) => (
          <option key={i}>{packageName}</option>
        ))}
      </select>
      <button
        className='modern'
        onClick={() => onSubmit({
          name,
          package: packageName,
          store: uuid(),
          args: {}
        })}
      >
        Add
      </button>
    </div>
  )
}
