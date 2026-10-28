<?php

namespace Laravel\Passport\ClientMetadata;

use GuzzleHttp\Psr7\Exception\MalformedUriException;
use GuzzleHttp\Psr7\Uri;

/**
 * @internal
 */
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
            $host = (new Uri($uri))->getHost();
        } catch (MalformedUriException) {
            return false;
        }

        $host = rtrim($host, '.');

        if ($host === 'localhost' || str_ends_with($host, '.localhost')) {
            return true;
        }

        if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            return str_starts_with($host, '127.');
        }

        $address = @inet_pton(trim($host, '[]'));

        return $address !== false && $address === inet_pton('::1');
    }
}
