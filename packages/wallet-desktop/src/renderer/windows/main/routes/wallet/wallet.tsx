
import { IconDefinition, faWallet } from '@fortawesome/free-solid-svg-icons'
import { Nav, NavIcon, Content } from '@wallet/renderer/components'

import { StatusBar } from './status-bar'
import { Wallets } from './wallets'

import './wallet.scss'

const { Route, Redirect } = ReactRouterDOM

interface WalletRoutes {
  icon: IconDefinition
  path: string
  title: string
  children: JSX.Element
}

export function Wallet (): JSX.Element {
  const routes: WalletRoutes[] = [
    { icon: faWallet, path: '/wallet/wallets', title: 'Explorer', children: <Wallets /> }
  ]
  const defaultPath = routes[0].path

  return (
    <div className='wallet'>
      <div className='app'>
        <Nav>
          {routes.map((route, i) => (
            <NavIcon key={i} {...route} />
          ))}
        </Nav>
        <Content>
          {routes.map((route, i) => (
            <Route key={i} path={route.path}>
              {route.children}
            </Route>
          ))}
          <Route path='/wallet' exact>
            <Redirect to={defaultPath} />
          </Route>
        </Content>
      </div>
      <StatusBar />
    </div>
  )
}
