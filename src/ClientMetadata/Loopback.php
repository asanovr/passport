<?php

namespace Laravel\Passport\ClientMetadata;

use League\Uri\Exceptions\SyntaxError;
use League\Uri\IPv4\Converter;
use League\Uri\Uri;
use Symfony\Component\HttpFoundation\IpUtils;

class Loopback
{
    /**
     * Determine if the given redirect address is on a loopback host, whatever its scheme.
     *
     * A loopback host is "localhost", any name below it, an address in "127.0.0.0/8", or "::1": where a
     * program on the user's computer is reached.
     */
    public static function isRedirect(string $uri): bool
    {
        try {
            $host = strtolower(rtrim(Uri::new($uri)->getHost() ?? '', '.'));
        } catch (SyntaxError) {
            return false;
        }

        if ($host === 'localhost' || str_ends_with($host, '.localhost')) {
            return true;
        }

        // A host that a browser reads as a number-based IPv4 address, such as "127.1", "2130706433" or "0x7f.0.0.1".
        if (! str_starts_with($host, '[')) {
            return str_starts_with((string) Converter::fromEnvironment()->toDecimal($host), '127.');
        }

        // An IPv4-mapped address (::ffff:127.0.0.1) is the IPv4 address it wraps.
        return IpUtils::checkIp(trim($host, '[]'), ['::1/128', '::ffff:127.0.0.0/104']);
    }
}
