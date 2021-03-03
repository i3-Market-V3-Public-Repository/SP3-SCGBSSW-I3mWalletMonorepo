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
        console.log('Browser echoes: ' + a);
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguYnJvd3Nlci5tb2QuanMiLCJzb3VyY2VzIjpbIi4uL3NyYy9lY2hvLnRzIiwiLi4vc3JjL3NpZ24udHMiXSwic291cmNlc0NvbnRlbnQiOm51bGwsIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUFBOzs7Ozs7Ozs7U0FTZ0IsSUFBSSxDQUFFLENBQVM7Ozs7SUFJYjtRQUNkLE9BQU8sQ0FBQyxHQUFHLENBQUMsa0JBQWtCLEdBQUcsQ0FBQyxDQUFDLENBQUE7S0FHcEM7O0lBRUQsT0FBTyxDQUFDLENBQUE7QUFDVjs7QUNqQkE7Ozs7Ozs7O0FBUU8sZUFBZSxJQUFJLENBQUUsQ0FBMkI7SUFDckQsTUFBTSxVQUFVLEdBQUcsTUFBTSxRQUFRLENBQUM7UUFDaEMsR0FBRyxFQUFFLE9BQU87UUFDWixHQUFHLEVBQUUsT0FBTztRQUNaLEdBQUcsRUFBRSxJQUFJO1FBQ1QsQ0FBQyxFQUFFLDZDQUE2QztRQUNoRCxDQUFDLEVBQUUsNkNBQTZDO1FBQ2hELENBQUMsRUFBRSw2Q0FBNkM7S0FDakQsQ0FBQyxDQUFBO0lBQ0YsTUFBTSxLQUFLLEdBQUcsQ0FBQyxPQUFPLENBQUMsS0FBSyxRQUFRLElBQUksQ0FBQyxJQUFJLFdBQVcsRUFBRSxFQUFFLE1BQU0sQ0FBQyxDQUFDLENBQUMsR0FBRyxJQUFJLFVBQVUsQ0FBQyxDQUFDLENBQUMsQ0FBQTtJQUV6RixNQUFNLEdBQUcsR0FBRyxNQUFNLElBQUksV0FBVyxDQUFDLEtBQUssQ0FBQztTQUNyQyxrQkFBa0IsQ0FBQyxFQUFFLEdBQUcsRUFBRSxPQUFPLEVBQUUsQ0FBQztTQUNwQyxJQUFJLENBQUMsVUFBVSxDQUFDLENBQUE7SUFFbkIsT0FBTyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQTtJQUNoQixPQUFPLEdBQUcsQ0FBQTtBQUNaOzs7OyJ9
