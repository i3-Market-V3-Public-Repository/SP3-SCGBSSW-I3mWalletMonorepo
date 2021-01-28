[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)


# my-package-name

This is an example README for your project. Please rewrite to your needs. Also, check the badges and remove if desired.

Don't remove the lines in section ## API reference documentation, since they are required to automatically include the API reference documentation of your module.

## Installation

`my-package-name` can be imported to your project with `npm`:

```bash
npm install my-package-name
```

NPM installation defaults to the ES6 module for browsers and the CJS one for Node.js. For web browsers, you can also directly download the IIFE bundle or the ESM bundle from the repository.

## Usage examples

Import your module as :

- Node.js

   ```javascript
   const myPackageName = require('my-package-name')
   ... // your code here
   ```

- JavaScript native or TypeScript project (including React and Angular)

   ```javascript
   import * as myPackageName from 'my-package-name'
   ... // your code here
   ```

   If you are using Angular, since this library uses node typings, you should also add them to the `angularCompilerOptions` in your `tsconfig.json`:

   ```json
     "angularCompilerOptions": {
       "types": ["node"]
       ...
     }
   ```

- JavaScript native browser ES module

   ```html
   <script type="module">
      import * as myPackageName from 'index.browser.bundle.mod.js'  // Use your actual path to the broser mod bundle that is in the dist directory
      ... // your code here
    </script>
   ```

- JavaScript native browser IIFE

   ```html
   <head>
     ...
     <script src="index.browser.bundle.iife.js"></script><!-- Use your actual path to the browser iife bundle that is in the dist directory -->
   </head>
   <body>
     ...
     <script>
       ... // your code here
     </script>
   </body>
   ```

An example of usage could be:

```javascript
YOUR JAVASCRIPT EXAMPLE CODE HERE
```

## API reference documentation

<a name="module_my-package-name"></a>

### my-package-name
My module description. Please update with your module data.

<a name="module_my-package-name..echo"></a>

#### my-package-name~echo(a) ⇒ <code>string</code>
Returns the input string

**Kind**: inner method of [<code>my-package-name</code>](#module_my-package-name)  
**Returns**: <code>string</code> - a gratifying echo response from either node or browser  

| Param | Type |
| --- | --- |
| a | <code>string</code> | 

