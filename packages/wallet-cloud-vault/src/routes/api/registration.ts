import { Request, Response, Router } from 'express'
import { OpenApiPaths } from '../../../types/openapi'
import { jwksPromise } from '../../config'
import { db } from '../../db'
import { jweDecrypt, JWK } from '@i3m/non-repudiation-library'

export default function (router: Router): void {
  router.get('/publicJwk',
    async (req: Request<{}, {}, {}, {}>, res: Response<OpenApiPaths.ApiV2RegistrationPublicJwk.Get.Responses.$200>, next) => { // eslint-disable-line @typescript-eslint/no-misused-promises
      try {
        const jwkPair = await jwksPromise
        res.json({ jwk: jwkPair.publicJwk })
      } catch (error) {
        return next(error)
      }
    }
  )
  router.get('/:data',
    async (req: Request<OpenApiPaths.ApiV2Registration$Data.Get.PathParameters, {}, {}, {}>, res: Response<OpenApiPaths.ApiV2Registration$Data.Get.Responses.$201>, next) => { // eslint-disable-line @typescript-eslint/no-misused-promises
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
          username: payload.username,
          auth_endpoint: '/api/v2/vault/auth'
        })
      } catch (error) {
        return next(error)
      }
    }
  )
}
