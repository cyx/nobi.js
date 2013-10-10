nobi
====

Node.js port of python's itsdangerous.

## Basic Usage

```javascript

var nobi = require('nobi');
var signer = nobi('mysecret-no-one-knows');

signer.sign('1');
// 1.T3t+woFyWyguMFMSwqEFS8KjwrvDvyceEQ==

signer.unsign('1.T3t+woFyWyguMFMSwqEFS8KjwrvDvyceEQ==')
// 1
```

## Timestamp Signer Usage

```javascript

var nobi = require('nobi');
var signer = nobi.timestampSigner('mysecret-no-one-knows');

signer.sign('1');
// 1.MTM4MDA4MDIxODA5MA==.PMO6Pxg/cXFZw4fDilTCkMKGw7zCgF9WWcOvKg==

// Try to unsign with maxAge of 1 second
signer.unsign('1.MTM4MDA4MDIxODA5MA==.PMO6Pxg/cXFZw4fDilTCkMKGw7zCgF9WWcOvKg==',
              { maxAge: 1000 })
// 1
```

## LICENSE

BSD
