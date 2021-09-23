const encode = (buf: Buffer): string => {
  return buf.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}

const decode = (str: string): Buffer => {
  return Buffer.from(str, 'base64')
}

export default {
  encode,
  decode
}
