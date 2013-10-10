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

    t.plan(1);

    var err;

    try {
        signer.unsign('foobar');
    }
    catch (e) {
        err = e;
    }

    t.ok(/Error: BadSignature/.test(err), 'bad signature check');
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

    t.ok(/Error: BadSignature/.test(err), 'tampered: bad signature');
});

test('nobi.timestamp signer', function (t) {
    var signer = nobi.timestampSigner('my secret');
    var signed = signer.sign('1');

    t.plan(1);

    t.equal('1', signer.unsign(signed, { maxAge: 1 }));
});

test('nobi.timestamp signer expired', function (t) {
    var signer = nobi.timestampSigner('my secret');
    var signed = signer.sign('1');

    t.plan(1);

    setTimeout(function () {
        try {
            t.equal('1', signer.unsign(signed, { maxAge: 1 }));
        } catch (err) {
            t.ok(/Error: BadSignature/.test(err), 'expired');
        }
    }, 5);
});

