import { faClipboard } from '@fortawesome/free-solid-svg-icons'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import { useAction } from '@wallet/renderer/communication'
import { useClipboard } from '@wallet/renderer/hooks/use-clipboard'
import * as React from 'react'

import { Accordion, Col, Form, InputGroup, Row } from 'react-bootstrap'
import './json-ui.scss'

interface InternalProps<T> {
  value: T
  prop: string
  fullProp: string
}

interface Props<T> {
  value: T
  prop: string
}

const labelWidth: number = 4 // maximum is 11 (label + content = 12)

function JsonArray (props: InternalProps<any[]>): JSX.Element {
  const { value, prop, fullProp } = props

  return (
    <Accordion.Item className='json-ui-array' eventKey={fullProp}>
      <Accordion.Header className='json-ui-array-header'>
        <label>{prop}</label>
      </Accordion.Header>
      <Accordion flush alwaysOpen>
        {value.map((item, i) => (
          <div className='json-ui-array-item' key={i.toString()}>
            <JsonProxy value={item} prop={i.toString()} fullProp={`${prop}.${i}`} />
          </div>
        ))}
      </Accordion>
    </Accordion.Item>
  )
}

function JsonObject (props: InternalProps<any>): JSX.Element {
  const { value, prop, fullProp } = props
  const entries = Object
    .entries(value)
    .sort(([a], [b]) => a > b ? 1 : b > a ? -1 : 0)

  return (
    <Accordion.Item className='json-ui-object' eventKey={fullProp}>
      <Accordion.Header className='settings-object-header'>
        {prop}
      </Accordion.Header>
      <Accordion.Body>
        {entries.map(([childProp, childValue]) => (
          <div key={childProp} className='settings-object-properties'>
            <JsonProxy value={childValue} prop={childProp} fullProp={`${prop}.${childProp}`} />
          </div>
        ))}
      </Accordion.Body>
    </Accordion.Item>
  )
}

function JsonText (props: InternalProps<string>): JSX.Element {
  const { prop, value, fullProp } = props
  const dispatch = useAction()
  const [writeClipboard] = useClipboard(dispatch)

  return (
    <Form.Group as={Row} className='json-ui-text' controlId={fullProp}>
      <Form.Label column sm={labelWidth} title={prop}>{prop}</Form.Label>
      <Col sm={12 - labelWidth}>
        <InputGroup>
          <Form.Control type='text' disabled size='sm' value={value} />
          <InputGroup.Text className='copy-button' onClick={() => writeClipboard(value.toString())}>
            <FontAwesomeIcon icon={faClipboard} />
          </InputGroup.Text>
        </InputGroup>
      </Col>
    </Form.Group>
  )
}

function JsonBoolean (props: InternalProps<boolean>): JSX.Element {
  const { prop, value, fullProp } = props

  return (
    <Form.Group as={Row} className='json-ui-boolean' controlId={fullProp}>
      <Form.Label column sm={labelWidth} title={prop}>{prop}</Form.Label>
      <Col sm={12 - labelWidth}>
        <Form.Switch disabled checked={value} />
      </Col>
    </Form.Group>
  )
}

function JsonNumber (props: InternalProps<number>): JSX.Element {
  const { prop, value, fullProp } = props
  const dispatch = useAction()
  const [writeClipboard] = useClipboard(dispatch)

  return (
    <Form.Group as={Row} className='json-ui-number' controlId={fullProp}>
      <Form.Label column sm={labelWidth} title={prop}>{prop}</Form.Label>
      <Col sm={12 - labelWidth}>
        <InputGroup>
          <Form.Control type='number' size='sm' value={value} disabled />
          <InputGroup.Text className='copy-button' onClick={() => writeClipboard(value.toString())}>
            <FontAwesomeIcon icon={faClipboard} />
          </InputGroup.Text>
        </InputGroup>
      </Col>
    </Form.Group>
  )
}

export function JsonProxy (props: InternalProps<any>): JSX.Element | null {
  const { value } = props

  if (value instanceof Object) {
    return <JsonObject {...props} />
  } else if (value instanceof Array) {
    return <JsonArray {...props} />
  } else if (typeof value === 'string') {
    return <JsonText {...props} />
  } else if (typeof value === 'boolean') {
    return <JsonBoolean {...props} />
  } else if (typeof value === 'number') {
    return <JsonNumber {...props} />
  } else {
    return null
  }
}

export function JsonUi (props: Props<any>): JSX.Element | null {
  const internalProps: InternalProps<any> = {
    ...props,
    fullProp: props.prop
  }

  return (
    <Accordion className='json-ui' flush alwaysOpen defaultActiveKey={[props.prop]}>
      <JsonProxy {...internalProps} />
    </Accordion>
  )
}
