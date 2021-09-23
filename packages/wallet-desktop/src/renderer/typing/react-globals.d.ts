import * as _ReactDOM from 'react-dom'
import * as _React from 'react'
import * as _ReactRouterDOM from 'react-router-dom'

declare global {
  type ReactDOM = typeof _ReactDOM
  type React = typeof _React
  const ReactRouterDOM: typeof _ReactRouterDOM
}
