
import * as React from 'react'

export const Wave = (): JSX.Element => {
  return (
    <>
      <div className='wave' />
      <div className='wave' style={{ animationDelay: '0.5s' }} />
    </>
  )
}
