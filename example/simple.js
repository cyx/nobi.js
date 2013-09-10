var nobi = require('../');
var signer = nobi('mysecret-no-one-knows');

var signed = signer.sign('1');
console.log(signed);

var unsigned = signer.unsign(signed);
console.log(unsigned);
