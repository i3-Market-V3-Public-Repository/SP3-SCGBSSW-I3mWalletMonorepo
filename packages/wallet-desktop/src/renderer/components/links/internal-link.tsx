import * as React from 'react'

interface Props {
  href: string
}

export function InternalLink (props: React.PropsWithChildren<Props>): JSX.Element {
  const { href } = props
  const children = props.children ?? href

  return (
    <a href={href} target='_blank'>
      {children}
    </a>
  )
}
