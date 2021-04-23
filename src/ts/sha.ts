const sha = async function (input: string|Uint8Array, algorithm = 'SHA-256'): Promise<string> {
  const algorithms = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']
  if (!algorithms.includes(algorithm)) {
    throw new RangeError(`Valid hash algorith values are any of ${JSON.stringify(algorithms)}`)
  }

  const encoder = new TextEncoder()
  const hashInput = (typeof input === 'string') ? encoder.encode(input).buffer : input

  let digest = ''
  if (IS_BROWSER) {
    const buf = await crypto.subtle.digest(algorithm, hashInput)
    const h = '0123456789abcdef';
    (new Uint8Array(buf)).forEach((v) => {
      digest += h[v >> 4] + h[v & 15]
    })
  } else {
    const nodeAlg = algorithm.toLowerCase().replace('-', '')
    digest = require('crypto').createHash(nodeAlg).update(Buffer.from(hashInput)).digest('hex') // eslint-disable-line
  }
  return digest
}
export { sha }
export default sha
