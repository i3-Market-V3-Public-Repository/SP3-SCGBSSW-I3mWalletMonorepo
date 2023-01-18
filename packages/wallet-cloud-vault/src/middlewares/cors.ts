import { RequestHandler } from 'express'
import { cors } from '../config'

export const corsMiddleware: RequestHandler = (req, res, next) => {
  res.header('Access-Control-Allow-Origin', cors.allowedOrigin)
  res.header('Access-Control-Allow-Headers', 'Authorization, Content-Type')
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
  res.header('Allow', 'GET, POST, OPTIONS')
  next()
}
