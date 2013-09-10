var scmp = require('scmp');
var crypto = require('crypto');
var util = require('util');

/**
 *  Usage:
 *
 *      var signer = nobi('my secret');
 *      signer.sign('string-to-sign');
 *
 *  Options:
 *
 *    opts.salt (default nobi.Signer)
 *    opts.sep (default '.')
 *    opts.digestMethod (default sha1)
*/
function nobi(secret, opts) {
    opts = opts || {};

    var salt = opts.salt || 'nobi.Signer';
    var sep = opts.sep || '.';
    var digestMethod = opts.digestMethod || 'sha1';
    var algorithm = HMACAlgorithm(digestMethod);

    var self = {
        sign: function (value) {
            return [value, sep, signature(value)].join('');
        },

        unsign: function (data) {
            var index = data.lastIndexOf(sep);

            if (index === -1) {
                fail('BadSignature: No %s found in value', sep);
            }

            var value = data.slice(0, index);
            var sig = data.slice(index + 1, data.length);

            if (scmp(sig, signature(value))) {
                return value;
            }

            fail('BadSignature: Signature %s does not match', sig);
        }
    };

    function deriveKey() {
        return algorithm(secret, salt);
    }

    function signature(value) {
        key = deriveKey();
        sig = algorithm(secret, salt);

        return new Buffer(sig).toString('base64');
    }

    return self;
}

function HMACAlgorithm(digestMethod) {
    function signature(key, data) {
        var hmac = crypto.createHmac(digestMethod, key);

        hmac.update(data);

        return hmac.digest('binary');
    }

    return signature;
}

function fail() {
    throw new Error(util.format.apply(null, arguments));
}

module.exports = nobi;

