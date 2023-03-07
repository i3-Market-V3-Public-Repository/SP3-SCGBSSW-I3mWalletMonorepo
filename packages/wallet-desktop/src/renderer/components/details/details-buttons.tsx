import * as React from 'react'

type Props = React.PropsWithChildren<{
  title: string
}>

export function DetailsButtons (props: Props): JSX.Element {
  const { title } = props

  return (
    <>
      <span className='details-label' title={title}>{title}</span>
      <div className='details-buttons'>{props.children}</div>
    </>
  )
}
