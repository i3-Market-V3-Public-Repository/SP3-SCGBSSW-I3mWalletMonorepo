import { WalletFunctionMetadata } from '@i3m/base-wallet'
import * as React from 'react'
import { Alert, Button } from 'react-bootstrap'

import { callWalletFunctionAction, WalletInfo } from '@wallet/lib'
import { useAction, useSharedMemory } from '@wallet/renderer/communication'
import { Details, Section } from '@wallet/renderer/components'
import { getProvider } from '@wallet/renderer/util'

interface Props {
  wallet: WalletInfo
}

export function WalletDetails (props: Props): JSX.Element {
  const { wallet } = props
  const [sharedMemory] = useSharedMemory()
  const dispatch = useAction()
  const walletMetadata = sharedMemory.walletsMetadata[wallet.package]

  const provider = getProvider(props.wallet.args.provider as string, sharedMemory)
  const providerName = provider?.name ?? 'Unknown'
  const walletFunctions = walletMetadata.functions.filter((metadata) => (metadata.scopes ?? ['wallet']).includes('wallet'))
  const developerFunctions = walletMetadata.functions.filter((metadata) => (metadata.scopes ?? []).includes('developer'))
  const enabled = wallet.name === sharedMemory.settings.wallet.current

  const executeWalletFunction = (walletFunction: WalletFunctionMetadata): void => {
    const action = callWalletFunctionAction.create(walletFunction)
    dispatch(action)
  }

  return (
    <Section title={wallet.name} scroll light>
      <Details>
        <Details.Body>
          <Details.Title>Summary</Details.Title>
          <Details.Grid>
            <Details.Input label='Name' value={wallet.name} />
            <Details.Input label='Type' value={walletMetadata.name} />
            <Details.Input label='Network' value={providerName} />
          </Details.Grid>
        </Details.Body>
        <Details.Separator />
        <Details.Body>
          <Details.Grid>
            {!enabled ? <Alert variant='info'>To enable the <b>wallet functions</b> for this wallet you must select it fist</Alert> : null}
            <Details.Buttons title='Wallet Functions'>
              {walletFunctions.map((walletFunction, i) => (
                <Button
                  disabled={!enabled}
                  onClick={() => executeWalletFunction(walletFunction)} key={i}
                >{walletFunction.name}
                </Button>
              ))}
            </Details.Buttons>
            {!enabled ? <Alert variant='info'>To enable the <b>developer functions</b> for this wallet you must select it fist</Alert> : null}
            <Details.Buttons title='Developer Functions'>
              {developerFunctions.map((walletFunction, i) => (
                <Button
                  disabled={!enabled}
                  onClick={() => executeWalletFunction(walletFunction)} key={i}
                >{walletFunction.name}
                </Button>
              ))}
            </Details.Buttons>
          </Details.Grid>
        </Details.Body>
      </Details>
    </Section>
  )
}
