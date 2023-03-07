import * as React from 'react'

import { joinClassNames } from '@wallet/renderer/util'
import { DetailsInput } from './details-input'
import { DetailsBody } from './details-body'
import { DetailsButtons } from './details-buttons'

import './details.scss'
import { DetailsTitle } from './details-title'
import { DetailsGrid } from './details-grid'
import { DetailsSeparator } from './details-separator'

type Props = React.PropsWithChildren<React.DetailedHTMLProps<React.HTMLAttributes<HTMLDivElement>, HTMLDivElement>>

export function Details (props: Props): JSX.Element {
  const { className, ...divProps } = props

  return (
    <div className={joinClassNames('details', className)} {...divProps}>
      {props.children}
    </div>
  )
}

Details.Body = DetailsBody
Details.Separator = DetailsSeparator
Details.Grid = DetailsGrid
Details.Input = DetailsInput
Details.Buttons = DetailsButtons
Details.Title = DetailsTitle
