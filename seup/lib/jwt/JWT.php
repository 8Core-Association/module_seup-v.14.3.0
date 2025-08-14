<?php
namespace Firebase\JWT;

class JWT {
    public static \$leeway = 0;
    public static \$timestamp = null;
    public static \$supported_algs = [
        'HS256' => ['hash_hmac', 'SHA256'],
    ];

    public static function decode(\$jwt, \$key, array \$allowed_algs = []) {
        if (empty(\$key)) throw new \InvalidArgumentException('Key may not be empty');
        \$tks = explode('.', \$jwt);
        if (count(\$tks) != 3) throw new \UnexpectedValueException('Wrong number of segments');

        list(\$headb64, \$bodyb64, \$cryptob64) = \$tks;
        \$header = json_decode(self::urlsafeB64Decode(\$headb64));
        \$payload = json_decode(self::urlsafeB64Decode(\$bodyb64));
        \$sig = self::urlsafeB64Decode(\$cryptob64);

        if (empty(\$header->alg)) throw new \DomainException('Empty algorithm');
        if (!in_array(\$header->alg, \$allowed_algs)) throw new \DomainException('Algorithm not allowed');

        if (!self::verify("\$headb64.\$bodyb64", \$sig, \$key, \$header->alg)) {
            throw new SignatureInvalidException('Signature verification failed');
        }

        return \$payload;
    }

    public static function encode(\$payload, \$key, \$alg = 'HS256') {
        \$header = ['typ' => 'JWT', 'alg' => \$alg];
        \$segments = [
            self::urlsafeB64Encode(json_encode(\$header)),
            self::urlsafeB64Encode(json_encode(\$payload))
        ];
        \$signing_input = implode('.', \$segments);
        \$signature = self::sign(\$signing_input, \$key, \$alg);
        \$segments[] = self::urlsafeB64Encode(\$signature);
        return implode('.', \$segments);
    }

    public static function sign(\$msg, \$key, \$alg) {
        list(\$function, \$algorithm) = self::\$supported_algs[\$alg];
        return hash_hmac(\$algorithm, \$msg, \$key, true);
    }

    public static function verify(\$msg, \$signature, \$key, \$alg) {
        \$expected = self::sign(\$msg, \$key, \$alg);
        return hash_equals(\$expected, \$signature);
    }

    public static function urlsafeB64Encode(\$input) {
        return str_replace('=', '', strtr(base64_encode(\$input), '+/', '-_'));
    }

    public static function urlsafeB64Decode(\$input) {
        \$remainder = strlen(\$input) % 4;
        if (\$remainder) \$input .= str_repeat('=', 4 - \$remainder);
        return base64_decode(strtr(\$input, '-_', '+/'));
    }
}