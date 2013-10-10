var scmp = require('scmp');
var crypto = require('crypto');
var format = require('util').format;

// This is used as the peg so the timestamps are smaller
// than what they need to be.
var EPOCH = 1293840000; // 2011/01/01 in UTC

// Usage:
//
//     var signer = nobi('my secret');
//     signer.sign('string-to-sign');
//
// Options:
//
//   opts.salt (default nobi.Signer)
//   opts.sep (default '.')
//   opts.digestMethod (default sha1)
//
function nobi(secret, opts) {
    opts = opts || {};

    var salt = opts.salt || 'nobi.Signer';
    var sep = opts.sep || '.';
    var digestMethod = opts.digestMethod || 'sha1';
    var algorithm = hmacAlgorithm(digestMethod);

    function sign(value) {
        return format('%s%s%s', value, sep,
                      signature(algorithm, secret, salt, value));
    }

    function unsign(data) {
        var tuple = rsplit(data, sep);

        var val = tuple[0];
        var sig = tuple[1];

        if (scmp(sig, signature(algorithm, secret, salt, val))) {
            return val;
        }

        fail('BadSignature: Signature appears to be tampered with');
    }

    return {
        sign: sign,
        unsign: unsign
    };
}

// Usage:
//
//     var signer = nobi.timestampSigner('my secret');
//     var signed = signer.sign('string-to-sign');
//
//     signer.unsign(signed, { maxAge: 60 }) // 60 ms
//
// Options:
//
//   opts.salt (default nobi.TimestampSigner)
//   opts.sep (default '.')
//   opts.digestMethod (default sha1)
//
function timestampSigner(secret, opts) {
    opts = opts || {};

    var salt = opts.salt || 'nobi.TimestampSigner';
    var sep = opts.sep || '.';
    var digestMethod = opts.digestMethod || 'sha1';

    var signer = nobi(secret, {
        salt: salt,
        sep: sep,
        digestMethod: digestMethod
    });

    function sign(data) {
        var timestamp = b64encode(String(getTimestamp()));
        var value = format('%s%s%s', data, sep, timestamp);

        return signer.sign(value);
    }

    function unsign(data, opts) {
        // the default maxAge is 60 seconds
        var maxAge = (opts && opts.maxAge) || 60000;

        // unsign the data. given something like:
        // 
        //     1.MTMMA==.PMO6Px==
        //
        // we get
        //
        //     1.MTMMA==
        //
        // as the unsigned value assuming it was unsigned
        // properly.
        var unsigned = signer.unsign(data);

        // We proceed to split the value and timestamp
        // here. So given:
        //
        //     1.MTMMA==
        //
        // The tuple will be:
        //
        //     ['1', 'MTMMA==']
        //
        var tuple = rsplit(unsigned, sep);

        // We call the values as `val` and `ts` henceforth.
        var val = tuple[0];
        var ts = tuple[1];

        // And properly convert the value of `ts` which is
        // originally base64 encoded into a Number.
        var timestamp = Number(b64decode(ts));

        var age = getTimestamp() - timestamp;

        if (age > maxAge) {
            fail('BadSignature: Signature Expired');
        }

        return val;
    }

    return {
        sign: sign,
        unsign: unsign
    };
}

// private functions

function rsplit(string, separator) {
    var index = string.lastIndexOf(separator);

    if (index === -1) {
        fail('BadSignature: Separator not found');
    }

    return [string.slice(0, index), string.slice(index + 1, string.length)];
}

function signature(algorithm, secret, salt, value) {
    var key = algorithm(secret, salt);
    var sig = algorithm(key, value);

    return b64encode(sig);
}

function getTimestamp() {
    return Date.now() - EPOCH;
}

function hmacAlgorithm(digestMethod) {
    function signature(key, data) {
        var hmac = crypto.createHmac(digestMethod, key);

        hmac.update(data);

        return hmac.digest('binary');
    }

    return signature;
}

function b64encode(string) {
    return new Buffer(string).toString('base64');
}

function b64decode(string) {
    return new Buffer(string, 'base64').toString();
}

function fail() {
    throw new Error(format.apply(null, arguments));
}

// Since `nobi` is the default usage, we just
// piggy back on it for the timestampSigner.
nobi.timestampSigner = timestampSigner;

// We export the main `nobi` function together with
// the piggybacked functions.
module.exports = nobi;

