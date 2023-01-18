import express from 'express'
import publicJwk from './public-key'

const router = express.Router()

export default async (): Promise<typeof router> => {
  publicJwk(router)

  return router
}
