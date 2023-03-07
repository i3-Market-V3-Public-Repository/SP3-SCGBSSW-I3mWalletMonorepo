import * as React from 'react'

import { faClipboard } from '@fortawesome/free-solid-svg-icons'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import { useAction } from '@wallet/renderer/communication'
import { useClipboard } from '@wallet/renderer/hooks/use-clipboard'
import { Form, InputGroup } from 'react-bootstrap'

interface Props {
  label: string
  value: string
}

export function DetailsInput (props: Props): JSX.Element {
  const { label, value } = props
  const dispatch = useAction()
  const [writeClipboard] = useClipboard(dispatch)

  return (
    <>
      <span className='details-label' title={label}>{label}</span>
      <InputGroup className='details-input'>
        <Form.Control type='text' size='sm' value={value} disabled />
        <InputGroup.Text className='copy-button' onClick={() => writeClipboard(value)}>
          <FontAwesomeIcon icon={faClipboard} />
        </InputGroup.Text>
      </InputGroup>
    </>
  )
}
