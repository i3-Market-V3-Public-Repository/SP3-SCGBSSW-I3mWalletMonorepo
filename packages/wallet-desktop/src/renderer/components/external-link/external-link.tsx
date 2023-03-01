import * as React from 'react'
interface Props {
  href: string
}

export function ExternalLink (props: React.PropsWithChildren<Props>): JSX.Element {
  const { href } = props
  const children = props.children ?? href

  const onClick: React.MouseEventHandler = async (ev) => {
    ev.preventDefault()
    await electron.shell.openExternal(href)
  }

  return (
    <a href='#' onClick={onClick}>
      {children}
    </a>
  )
}
