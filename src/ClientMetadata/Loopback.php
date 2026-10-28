<?php

namespace Laravel\Passport\ClientMetadata;

use GuzzleHttp\Psr7\Exception\MalformedUriException;
use GuzzleHttp\Psr7\Uri;

/**
 * @internal
 */
final class Loopback
{
    /**
     * The hosts a program on the user's computer is reached at.
     *
     * @var string[]
     */
    public const HOSTS = ['127.0.0.1', '[::1]', 'localhost'];

    /**
     * Determine if the given redirect address is on a loopback host, whatever its scheme.
     */
    public static function isRedirect(string $uri): bool
    {
        try {
            $uri = new Uri($uri);
        } catch (MalformedUriException) {
            return false;
        }

        return in_array($uri->getHost(), static::HOSTS, true);
    }
}
