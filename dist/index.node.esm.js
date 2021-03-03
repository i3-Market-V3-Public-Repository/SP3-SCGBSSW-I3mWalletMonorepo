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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5lc20uanMiLCJzb3VyY2VzIjpbIi4uL3NyYy9lY2hvLnRzIiwiLi4vc3JjL3NpZ24udHMiXSwic291cmNlc0NvbnRlbnQiOm51bGwsIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUFBOzs7Ozs7Ozs7U0FTZ0IsSUFBSSxDQUFFLENBQVM7Ozs7SUFNdEI7UUFDTCxPQUFPLENBQUMsR0FBRyxDQUFDLGtCQUFrQixHQUFHLENBQUMsQ0FBQyxDQUFBO0tBQ3BDOztJQUVELE9BQU8sQ0FBQyxDQUFBO0FBQ1Y7O0FDakJBOzs7Ozs7OztBQVFPLGVBQWUsSUFBSSxDQUFFLENBQTJCO0lBQ3JELE1BQU0sVUFBVSxHQUFHLE1BQU0sUUFBUSxDQUFDO1FBQ2hDLEdBQUcsRUFBRSxPQUFPO1FBQ1osR0FBRyxFQUFFLE9BQU87UUFDWixHQUFHLEVBQUUsSUFBSTtRQUNULENBQUMsRUFBRSw2Q0FBNkM7UUFDaEQsQ0FBQyxFQUFFLDZDQUE2QztRQUNoRCxDQUFDLEVBQUUsNkNBQTZDO0tBQ2pELENBQUMsQ0FBQTtJQUNGLE1BQU0sS0FBSyxHQUFHLENBQUMsT0FBTyxDQUFDLEtBQUssUUFBUSxJQUFJLENBQUMsSUFBSSxXQUFXLEVBQUUsRUFBRSxNQUFNLENBQUMsQ0FBQyxDQUFDLEdBQUcsSUFBSSxVQUFVLENBQUMsQ0FBQyxDQUFDLENBQUE7SUFFekYsTUFBTSxHQUFHLEdBQUcsTUFBTSxJQUFJLFdBQVcsQ0FBQyxLQUFLLENBQUM7U0FDckMsa0JBQWtCLENBQUMsRUFBRSxHQUFHLEVBQUUsT0FBTyxFQUFFLENBQUM7U0FDcEMsSUFBSSxDQUFDLFVBQVUsQ0FBQyxDQUFBO0lBRW5CLE9BQU8sQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLENBQUE7SUFDaEIsT0FBTyxHQUFHLENBQUE7QUFDWjs7OzsifQ==
