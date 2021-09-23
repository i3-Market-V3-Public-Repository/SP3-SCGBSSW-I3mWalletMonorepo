import { joinClassNames } from '@wallet/renderer/util'

import './horizontal-accordion.scss'

type AccordionProps = React.DetailedHTMLProps<React.HTMLAttributes<HTMLDivElement>, HTMLDivElement>

export function HorizontalAccordion (props: AccordionProps): JSX.Element {
  const { className, ...extraProps } = props

  return (
    <div className={joinClassNames('horizontal-accordion', className)} {...extraProps}>
      {props.children}
    </div>
  )
}
