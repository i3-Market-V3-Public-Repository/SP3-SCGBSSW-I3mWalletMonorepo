import { joinClassNames } from '@wallet/renderer/util'

import './horizontal-accordion.scss'

type AccordionProps = React.DetailedHTMLProps<React.HTMLAttributes<HTMLDivElement>, HTMLDivElement>

export function Fixed (props: AccordionProps): JSX.Element {
  const { className, ...extraProps } = props

  return (
    <div className={joinClassNames('accordion-fixed', className)} {...extraProps}>
      {props.children}
    </div>
  )
}
