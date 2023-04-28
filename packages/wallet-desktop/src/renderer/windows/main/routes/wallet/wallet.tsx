
import * as ReactRouterDOM from 'react-router-dom'
import * as React from 'react'

import { IconDefinition, faWallet, faCog, faLink, faCloud, faBugSlash } from '@fortawesome/free-solid-svg-icons'
import { Nav, NavIcon, Content } from '@wallet/renderer/components'

import { StatusBar } from './status-bar'
import { Explorer } from './explorer'
import { Settings } from './settings'
import { Connect } from './connect'
import { CloudVault } from './cloud-vault'
import { Debug } from './debug'

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
    { icon: faWallet, path: '/wallet/explorer', title: 'Explorer', children: <Explorer /> },
    { icon: faLink, path: '/wallet/connect', title: 'Connect', children: <Connect /> },
    { icon: faCloud, path: '/wallet/cloud-vault', title: 'Cloud Vault', children: <CloudVault /> },
    { icon: faCog, path: '/wallet/settings', title: 'Settings', children: <Settings /> }
  ]
  const defaultPath = routes[0].path

  if (process.env.NODE_ENV === 'development') {
    routes.push({ icon: faBugSlash, path: '/wallet/debug', title: 'Debug', children: <Debug /> })
  }

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
