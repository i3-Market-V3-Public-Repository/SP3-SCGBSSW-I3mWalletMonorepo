import { joinClassNames } from '@wallet/renderer/util'

type Props = React.PropsWithChildren<{
  onClick?: () => void
}>

export function StatusBarItem (props: Props): JSX.Element {
  const clickable = props.onClick !== undefined
  const onClick = props.onClick ?? (() => {})

  return (
    <div className={joinClassNames('status-bar-item', clickable ? 'clickable' : undefined)} onClick={onClick}>
      {props.children}
    </div>
  )
}
