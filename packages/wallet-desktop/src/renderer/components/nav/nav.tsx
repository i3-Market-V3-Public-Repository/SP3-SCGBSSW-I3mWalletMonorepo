
import './nav.scss'

export function Nav (props: React.PropsWithChildren<{}>): JSX.Element {
  return (
    <div className='nav'>
      {props.children}
    </div>
  )
}
