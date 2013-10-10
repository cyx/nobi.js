var scmp = require('scmp');
var crypto = require('crypto');
var util = require('util');

// This is used as peg so the timestamps are smaller
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

    var self = {
        sign: function (value) {
            return [value, sep, this._signature(value)].join('');
        },

        unsign: function (data) {
            var index = data.lastIndexOf(sep);

            if (index === -1) {
                fail('BadSignature: No %s found in value', sep);
            }

            var value = data.slice(0, index);
            var sig = data.slice(index + 1, data.length);

            if (scmp(sig, this._signature(value))) {
                return value;
            }

            fail('BadSignature: Signature %s does not match', sig);
        },

        _deriveKey: function () {
            return algorithm(secret, salt);
        },

        _signature: function (value) {
            var key = this._deriveKey();
            var sig = algorithm(key, value);

            return new Buffer(sig).toString('base64');
        }
    };

    return self;

}

// Usage:
//
//     var signer = nobi.timestampSigner('my secret');
//     signer.sign('string-to-sign');
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

    var self = {
        sign: function (value) {
            var timestamp = b64encode(String(getTimestamp()));

            value = [value, sep, timestamp].join('');

            return [value, sep, signer._signature(value)].join('');
        },

        unsign: function (data, opts) {
            var maxAge = (opts && opts.maxAge) || 60000;
            var unsigned = signer.unsign(data);
            var index = unsigned.lastIndexOf(sep);

            if (index === -1) {
                fail('BadSignature: No %s found in value', sep);
            }

            var value = unsigned.slice(0, index);
            var ts = unsigned.slice(index + 1, unsigned.length);
            var timestamp = Number(b64decode(ts));
            var age = getTimestamp() - timestamp;

            if (age > maxAge) {
                fail('BadSignature: Signature Expired', value);
            }

            return value;
        }
    };

    return self;
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
    throw new Error(util.format.apply(null, arguments));
}

nobi.timestampSigner = timestampSigner;

module.exports = nobi;

