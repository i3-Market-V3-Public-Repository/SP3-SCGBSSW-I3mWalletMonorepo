// import { HttpError } from 'express-openapi-validator/dist/framework/types'
import { Passport } from 'passport'
import { Strategy, ExtractJwt } from 'passport-jwt'
import { Issuer, Strategy as OidcStrategy, TokenSet } from 'openid-client'
import { jwt, oidcConfig } from '../config/index.js'

export interface User {
  username: string
}

const issuer = await Issuer.discover(oidcConfig.providerUri)
console.log('Discovered issuer %s %O', issuer.issuer, issuer.metadata)

const client = new issuer.Client(oidcConfig.client)

export const passport = new Passport()
passport.use('jwtBearer', new Strategy(
  {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: jwt.secret
  },
  (jwtPayload, done) => {
    try {
      const user: User = {
        username: jwtPayload.username
      }
      return done(null, user)
      // return done(new HttpError({
      //   status: 401,
      //   name: 'unauthorized',
      //   path: ''
      // }))
    } catch (error) {
      return done(error)
    }
  }
))

passport.use('oidc',
  new OidcStrategy(
    {
      client,
      usePKCE: false
    }, (token: TokenSet, done: Function) => {
      return done(null, token)
    }
  )
)
