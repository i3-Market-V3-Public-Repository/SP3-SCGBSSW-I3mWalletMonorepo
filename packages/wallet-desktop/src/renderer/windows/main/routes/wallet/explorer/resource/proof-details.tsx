import * as React from 'react'

import { NonRepudiationProofResource } from '@i3m/base-wallet'
import { NrProofPayload } from '@i3m/non-repudiation-library/types'
import { decodeJwt } from 'jose'

interface Props {
  resource: NonRepudiationProofResource
}

export function ProofDetails (props: Props): JSX.Element {
  const { resource } = props
  const proofPayload = decodeJwt(resource.resource) as unknown as NrProofPayload

  return (
    <div className='details-body'>
      {resource.name !== undefined
        ? (
          <div className='details-param inline'>
            <span>Name:</span>
            <input type='text' disabled value={resource.name} />
          </div>
        ) : null}
      <div className='details-param inline'>
        <span>Id:</span>
        <input type='text' disabled value={resource.id} />
      </div>
      <div className='details-param inline'>
        <span>Type:</span>
        <input type='text' disabled value={'Proof: ' + proofPayload.proofType} />
      </div>
      <div className='details-param expand'>
        <span>Data:</span>
        <textarea disabled value={JSON.stringify({ claims: proofPayload, jws: resource.resource }, undefined, 2)} />
      </div>
    </div>
  )
}
