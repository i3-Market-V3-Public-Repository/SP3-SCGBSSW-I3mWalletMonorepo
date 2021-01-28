/**
 * My module description. Please update with your module data.
 * @module my-package-name
 */

/**
 * Returns the input string
 *
 * @param {string} a
 *
 * @returns {string} a gratifying echo response from either node or browser
 */
export function echo (a: string): string {
  /* Every if else block with isBrowser (different code for node and browser) should disable eslint rule no-lone-blocks
  */
  /* eslint-disable no-lone-blocks */
  if (process.env.BROWSER === 'true') {
    console.log('Browser echoes: ' + a)
  } else {
    console.log('Node.js echoes: ' + a)
  }
  /* eslint-enable no-lone-blocks */
  return a
}
