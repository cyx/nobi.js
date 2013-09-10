var test = require('tape');
var nobi = require('../');

test('nobi.signer', function (t) {
    var signer = nobi('my secret');
    var signed = signer.sign('1');

    t.plan(1);
    t.equal('1', signer.unsign(signed));
});

test('nobi.signer invalid string', function (t) {
    var signer = nobi('my secret');
    var signed = signer.sign('1');

    t.plan(1);

    var err;

    try {
        signer.unsign('foobar');
    }
    catch (e) {
        err = e;
    }

    t.ok(/Error: BadSignature/.test(err), 'exception raised');
});

test('nobi.signer tampered signed string', function (t) {
    var signer = nobi('my secret');
    var signed = signer.sign('1');

    t.plan(1);

    var err;

    try {
        signer.unsign(signed + ' ');
    }
    catch (e) {
        err = e;
    }

    t.ok(/Error: BadSignature/.test(err), 'exception raised');
});

