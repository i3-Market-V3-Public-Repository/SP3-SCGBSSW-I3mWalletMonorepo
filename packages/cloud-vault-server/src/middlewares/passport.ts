// import { HttpError } from 'express-openapi-validator/dist/framework/types'
import { IdTokenClaims, Issuer, Strategy as OidcStrategy, TokenSet } from 'openid-client'
import passport from 'passport'
import { ExtractJwt, Strategy as JwtStrategy } from 'passport-jwt'
import { jwt, oidcConfig } from '../config'
import { decode } from 'jsonwebtoken'

export interface User {
  username: string
}

export interface RegistrationUser {
  idToken: string
  claims: string[]
  did: string
  scope: string
}

async function passportPromiseFn (): Promise<typeof passport> {
  const issuer = await Issuer.discover(oidcConfig.providerUri)
  console.log('Discovered issuer %s %O', issuer.issuer, issuer.metadata)

  const client = new issuer.Client(oidcConfig.client)

  passport.use('jwtBearer', new JwtStrategy(
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
        usePKCE: false,
        passReqToCallback: true
      },
      (req: any, token: TokenSet, done: Function) => {
        const idToken = token.id_token
        if (idToken === undefined) {
          const err = new Error('no id_token')
          return done(err, undefined)
        }

        const scope = token.scope
        // const iss = claims.iss
        if (scope === undefined) {
          const err = Error('no scope in token')
          return done(err, undefined)
        }

        try {
          const claims = token.claims()
          const did = claims.sub
          const user: RegistrationUser = {
            idToken,
            scope,
            claims: extractClaims(claims),
            did
          }
          return done(null, user)
        } catch (error) {
          return done(error, undefined)
        }
      }
    )
  )
  return passport
}

export const passportPromise = passportPromiseFn()

interface VerifiableCredential {
  credentialSubject: { [p: string]: boolean }
  '@context': string[]
  type: string[]
  credentialStatus: { id: string, type: string }
  sub: string
  nbf: number
  iss: string
}

function extractClaims (claims: IdTokenClaims): string[] {
  const verifiedClaims = claims.verified_claims as { trusted: string[], untrusted: string[] } | undefined
  if (verifiedClaims === undefined) return []
  const claimsTitles: string[] = []
  if (verifiedClaims.trusted.length > 0) claimsTitles.push(...decodeAndValidateClaims(verifiedClaims.trusted))
  if (verifiedClaims.untrusted.length > 0) claimsTitles.push(...decodeAndValidateClaims(verifiedClaims.untrusted))
  return claimsTitles
}

function decodeAndValidateClaims (vc: string[]): string[] {
  const claims: string[] = []
  const decodeVC: VerifiableCredential[] = vc.map(v => ((decode(v) as { [p: string]: unknown }).vc as VerifiableCredential))
  decodeVC.forEach(v => {
    claims.push(...Object.keys(v.credentialSubject).filter(k => v.credentialSubject[k]))
  })
  return claims
}
