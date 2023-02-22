import { Request, Response, Router } from 'express'
import { OpenApiPaths } from '../../../types/openapi'
import { jwksPromise } from '../../config'
import { dbFunctions as db } from '../../db'
import { jweDecrypt, JWK } from '@i3m/non-repudiation-library'
import { HttpError } from 'express-openapi-validator/dist/framework/types'

export default function (router: Router): void {
  router.get('/public-jwk',
    async (req: Request<{}, {}, {}, {}>, res: Response<OpenApiPaths.ApiV2RegistrationPublicJwk.Get.Responses.$200>, next) => { // eslint-disable-line @typescript-eslint/no-misused-promises
      try {
        const jwkPair = await jwksPromise
        res.json({ jwk: jwkPair.publicJwk })
      } catch (error: any) {
        return next(error)
      }
    }
  )
  router.get('/register/:data',
    async (req: Request<OpenApiPaths.ApiV2RegistrationRegister$Data.Get.PathParameters, {}, {}, {}>, res: Response<OpenApiPaths.ApiV2RegistrationRegister$Data.Get.Responses.$201>, next) => { // eslint-disable-line @typescript-eslint/no-misused-promises
      try {
        // TO-DO
        console.log(req.params.data)
        const jwkPair = await jwksPromise
        const { plaintext } = await jweDecrypt(req.params.data, jwkPair.privateJwk as JWK)
        const payload = JSON.parse(Buffer.from(plaintext).toString('utf-8'))
        if (!('username' in payload) || !('authkey' in payload) || !('did' in payload)) {
          throw new Error('invalid data for registration')
        }
        await db.registerUser(payload.did, payload.username, payload.authkey)
        res.status(201).json({
          status: 'created',
          username: payload.username
        })
      } catch (error) {
        if (error !== null && typeof error === 'object' && 'code' in error && error.code === '23505') {
          const err = new HttpError({
            status: 400,
            message: 'user already registered',
            name: 'already-registered',
            path: req.path
          })
          return next(err)
        }
        return next(error)
      }
    }
  )

  router.get('/deregister',
    async (req: Request, res: Response<OpenApiPaths.ApiV2RegistrationDeregister.Get.Responses.$204>, next) => { // eslint-disable-line @typescript-eslint/no-misused-promises
      // TO-DO: get did from id_token
      const did = 'did:ethr:i3m:0x02c1e51dbe7fa3c3e89df33495f241316d9554b5206fcef16d8108486285e38c27'
      await db.deleteStorageByDid(did).catch((err) => {
        if (err instanceof Error && err.message === 'not-registered') {
          const err = new HttpError({
            status: 404,
            message: 'this identity (DID) is not registered',
            name: 'not-registered',
            errors: [],
            path: req.path
          })
          return next(err)
        }
        return next(err)
      })
      res.status(204).end()
    }
  )
}
