nobi
====

Node.js port of python's itsdangerous.

## Usage

```javascript

var nobi = require('nobi');
var signer = nobi('mysecret-no-one-knows');

signer.sign('1');
// 1.T3t+woFyWyguMFMSwqEFS8KjwrvDvyceEQ==

signer.unsign('1.T3t+woFyWyguMFMSwqEFS8KjwrvDvyceEQ==')
// 1
```

## TODO

- [ ] Timestamp signer

## LICENSE

BSD
