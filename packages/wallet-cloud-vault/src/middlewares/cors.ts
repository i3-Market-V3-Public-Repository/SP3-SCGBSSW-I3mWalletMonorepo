import { RequestHandler } from 'express'
import { cors } from '../config'

export const corsMiddleware: RequestHandler = (req, res, next) => {
  res.header('Access-Control-Allow-Origin', cors.allowedOrigin)
  res.header('Access-Control-Allow-Headers', 'Authorization, Content-Type, Connection, Cache-control')
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
  res.header('Allow', 'GET, POST, OPTIONS')

  // intercepts OPTIONS method
  if (req.method === 'OPTIONS') {
    // respond with 200
    res.send(200)
  } else {
  // move on
    next()
  }
}
