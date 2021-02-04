import CompactSign from 'jose/jws/compact/sign';
import parseJwk from 'jose/jwk/parse';

/**
 * Returns the input string
 *
 * @param {string} a
 *
 * @returns {string} a gratifying echo response from either node or browser
 */
function echo(a) {
    /* Every if else block with isBrowser (different code for node and browser) should disable eslint rule no-lone-blocks
    */
    /* eslint-disable no-lone-blocks */
    {
        console.log('Node.js echoes: ' + a);
    }
    /* eslint-enable no-lone-blocks */
    return a;
}

async function sign(a) {
    const encoder = new TextEncoder();
    const privateKey = await parseJwk({
        alg: 'ES256',
        crv: 'P-256',
        kty: 'EC',
        d: 'VhsfgSRKcvHCGpLyygMbO_YpXc7bVKwi12KQTE4yOR4',
        x: 'ySK38C1jBdLwDsNWKzzBHqKYEE5Cgv-qjWvorUXk9fw',
        y: '_LeQBw07cf5t57Iavn4j-BqJsAD1dpoz8gokd3sBsOo'
    });
    const jws = await new CompactSign(encoder.encode(JSON.stringify({ msg: 'It’s a dangerous business, Frodo, going out your door.' })))
        .setProtectedHeader({ alg: 'ES256' })
        .sign(privateKey);
    console.log(jws);
    return jws;
}

export { echo, sign };
//# sourceMappingURL=index.node.esm.js.map
