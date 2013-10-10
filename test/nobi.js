var test = require('tape');
var nobi = require('../');

var signer = nobi('my secret');

test('basic: sign + unsign', function (t) {
    t.plan(1);

    var signed = signer.sign('1');

    t.equal('1', signer.unsign(signed));
});

test('basic: unsign invalid string', function (t) {
    t.plan(1);

    t.throws(function () {
        signer.unsign('foobar');
    }, /BadSignature/);
});

test('basic: unsign tampered string', function (t) {
    t.plan(1);

    var signed = signer.sign('1');

    t.throws(function () {
        signer.unsign(signed + 'tamper');
    }, /BadSignature/);
});

var timestampSigner = nobi.timestampSigner('my secret');

test('nobi.timestamp signer', function (t) {
    var signed = timestampSigner.sign('1');

    t.plan(1);
    t.equal('1', timestampSigner.unsign(signed, { maxAge: 1 }));
});

test('nobi.timestamp invalid string', function (t) {
    t.plan(1);

    t.throws(function () {
        timestampSigner.unsign('foobar', { maxAge: 1 });
    }, /BadSignature/);
});

test('nobi.timestamp tampered string', function (t) {
    t.plan(1);

    var signed = timestampSigner.sign('1');

    t.throws(function () {
        timestampSigner.unsign(signed + 'tamper', { maxAge: 1 });
    }, /BadSignature/);
});

test('nobi.timestamp signer expired', function (t) {
    var signer = nobi.timestampSigner('my secret');
    var signed = signer.sign('1');

    t.plan(1);

    setTimeout(function () {
        t.throws(function () {
            signer.unsign(signed, { maxAge: 1 });
        }, /BadSignature/);
    }, 5);
});

