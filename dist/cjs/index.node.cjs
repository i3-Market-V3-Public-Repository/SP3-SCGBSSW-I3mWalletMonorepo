'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var CompactSign = require('jose/jws/compact/sign');
var parseJwk = require('jose/jwk/parse');

function _interopDefaultLegacy (e) { return e && typeof e === 'object' && 'default' in e ? e : { 'default': e }; }

var CompactSign__default = /*#__PURE__*/_interopDefaultLegacy(CompactSign);
var parseJwk__default = /*#__PURE__*/_interopDefaultLegacy(parseJwk);

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
    const privateKey = await parseJwk__default['default']({
        alg: 'ES256',
        crv: 'P-256',
        kty: 'EC',
        d: 'VhsfgSRKcvHCGpLyygMbO_YpXc7bVKwi12KQTE4yOR4',
        x: 'ySK38C1jBdLwDsNWKzzBHqKYEE5Cgv-qjWvorUXk9fw',
        y: '_LeQBw07cf5t57Iavn4j-BqJsAD1dpoz8gokd3sBsOo'
    });
    const input = (typeof a === 'string') ? (new TextEncoder()).encode(a) : new Uint8Array(a);
    const jws = await new CompactSign__default['default'](input)
        .setProtectedHeader({ alg: 'ES256' })
        .sign(privateKey);
    console.log(jws);
    return jws;
}

exports.echo = echo;
exports.sign = sign;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5janMiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9lY2hvLnRzIiwiLi4vLi4vc3JjL3NpZ24udHMiXSwic291cmNlc0NvbnRlbnQiOm51bGwsIm5hbWVzIjpbInBhcnNlSndrIiwiQ29tcGFjdFNpZ24iXSwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7OztBQUFBOzs7Ozs7Ozs7U0FTZ0IsSUFBSSxDQUFFLENBQVM7Ozs7SUFNdEI7UUFDTCxPQUFPLENBQUMsR0FBRyxDQUFDLGtCQUFrQixHQUFHLENBQUMsQ0FBQyxDQUFBO0tBQ3BDOztJQUVELE9BQU8sQ0FBQyxDQUFBO0FBQ1Y7O0FDakJBOzs7Ozs7OztBQVFPLGVBQWUsSUFBSSxDQUFFLENBQTJCO0lBQ3JELE1BQU0sVUFBVSxHQUFHLE1BQU1BLDRCQUFRLENBQUM7UUFDaEMsR0FBRyxFQUFFLE9BQU87UUFDWixHQUFHLEVBQUUsT0FBTztRQUNaLEdBQUcsRUFBRSxJQUFJO1FBQ1QsQ0FBQyxFQUFFLDZDQUE2QztRQUNoRCxDQUFDLEVBQUUsNkNBQTZDO1FBQ2hELENBQUMsRUFBRSw2Q0FBNkM7S0FDakQsQ0FBQyxDQUFBO0lBQ0YsTUFBTSxLQUFLLEdBQUcsQ0FBQyxPQUFPLENBQUMsS0FBSyxRQUFRLElBQUksQ0FBQyxJQUFJLFdBQVcsRUFBRSxFQUFFLE1BQU0sQ0FBQyxDQUFDLENBQUMsR0FBRyxJQUFJLFVBQVUsQ0FBQyxDQUFDLENBQUMsQ0FBQTtJQUV6RixNQUFNLEdBQUcsR0FBRyxNQUFNLElBQUlDLCtCQUFXLENBQUMsS0FBSyxDQUFDO1NBQ3JDLGtCQUFrQixDQUFDLEVBQUUsR0FBRyxFQUFFLE9BQU8sRUFBRSxDQUFDO1NBQ3BDLElBQUksQ0FBQyxVQUFVLENBQUMsQ0FBQTtJQUVuQixPQUFPLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxDQUFBO0lBQ2hCLE9BQU8sR0FBRyxDQUFBO0FBQ1o7Ozs7OyJ9
