import { WalletFunctionMetadata } from '@i3-market/base-wallet'
import { WalletInfo, callWalletFunctionAction } from '@wallet/lib'
import { useSharedMemory, useAction } from '@wallet/renderer/communication'
import { Extendible, Section } from '@wallet/renderer/components'

interface Props {
  wallet: WalletInfo
}

export function WalletDetails (props: Props): JSX.Element {
  const { wallet } = props
  const [sharedMemory] = useSharedMemory()
  const dispatch = useAction()
  const walletMetadata = sharedMemory.walletsMetadata[wallet.package]

  const provider = sharedMemory.settings.providers.find((provider) => provider.provider === wallet.args.provider)
  const walletFunctions = walletMetadata.functions.filter((metadata) => (metadata.scopes ?? ['wallet']).includes('wallet'))
  const developerFunctions = walletMetadata.functions.filter((metadata) => (metadata.scopes ?? []).includes('developer'))

  const executeWalletFunction = (walletFunction: WalletFunctionMetadata): void => {
    const action = callWalletFunctionAction.create(walletFunction)
    dispatch(action)
  }

  return (
    <Extendible className='details'>
      <Section title='Details'>
        <div className='details-body'>
          <div className='details-param inline'>
            <span>Name:</span>
            <input type='text' disabled value={wallet.name} />
          </div>
          <div className='details-param'>
            <span>Type:</span>
            <input type='text' disabled value={walletMetadata.name} />
          </div>
          <div className='details-param'>
            <span>Provider:</span>
            <input type='text' disabled value={provider?.name ?? 'Unknown'} />
          </div>
          <div className='details-param'>
            <span className='details-title'>Wallet Functions</span>
            <div className='details-buttons'>
              {walletFunctions.map((walletFunction, i) => (
                <button onClick={() => executeWalletFunction(walletFunction)} key={i}>{walletFunction.name}</button>
              ))}
            </div>
          </div>
          {sharedMemory.settings.developer.enableDeveloperFunctions === true ? (
            <div className='details-param'>
              <span className='details-title'>Developer Functions</span>
              <div className='details-buttons'>
                {developerFunctions.map((walletFunction, i) => (
                  <button onClick={() => executeWalletFunction(walletFunction)} key={i}>{walletFunction.name}</button>
                ))}
              </div>
            </div>
          ) : null}
        </div>
      </Section>
    </Extendible>
  )
}
