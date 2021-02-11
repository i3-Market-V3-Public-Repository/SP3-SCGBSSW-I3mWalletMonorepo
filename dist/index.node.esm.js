import CompactSign from 'jose/jws/compact/sign';
import parseJwk from 'jose/jwk/parse';

/**
 * Returns the input string
 *
 * @remarks An example echo function that runs differently in Node and Browser javascript
 *
 * @param a - the text to echo
 *
 * @returns a gratifying echo response from either node or browser
 */
function echo(a) {
    /* Every if else block with isBrowser (different code for node and browser)
       should disable eslint rule no-lone-blocks */
    /* eslint-disable no-lone-blocks */
    {
        console.log('Node.js echoes: ' + a);
    }
    /* eslint-enable no-lone-blocks */
    return a;
}

/**
 * Signs input and returns compact JWS
 *
 * @param a - the input to sign
 *
 * @returns a promise that resolves to a compact JWS
 *
 */
async function sign(a) {
    const privateKey = await parseJwk({
        alg: 'ES256',
        crv: 'P-256',
        kty: 'EC',
        d: 'VhsfgSRKcvHCGpLyygMbO_YpXc7bVKwi12KQTE4yOR4',
        x: 'ySK38C1jBdLwDsNWKzzBHqKYEE5Cgv-qjWvorUXk9fw',
        y: '_LeQBw07cf5t57Iavn4j-BqJsAD1dpoz8gokd3sBsOo'
    });
    const input = (typeof a === 'string') ? (new TextEncoder()).encode(a) : new Uint8Array(a);
    const jws = await new CompactSign(input)
        .setProtectedHeader({ alg: 'ES256' })
        .sign(privateKey);
    console.log(jws);
    return jws;
}

export { echo, sign };
//# sourceMappingURL=index.node.esm.js.map
