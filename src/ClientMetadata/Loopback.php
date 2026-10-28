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

        if (($first = static::numericIPv4FirstOctet($host)) !== null) {
            return $first === 127;
        }

        $address = @inet_pton(trim($host, '[]'));

        if ($address === false || strlen($address) !== 16) {
            return false;
        }

        // An IPv4-mapped address (::ffff:127.0.0.1) is the IPv4 address it wraps.
        if (str_starts_with($address, str_repeat("\0", 10)."\xff\xff")) {
            return ord($address[12]) === 127;
        }

        return $address === inet_pton('::1');
    }

    /**
     * Get the first octet of a host that a browser reads as a number-based IPv4 address, such as "127.1",
     * "2130706433" or "0x7f.0.0.1", or null if the host is not written that way.
     */
    protected static function numericIPv4FirstOctet(string $host): ?int
    {
        $parts = explode('.', $host);

        if (count($parts) > 4) {
            return null;
        }

        $numbers = [];

        foreach ($parts as $part) {
            if (preg_match('/^(?:0x[0-9a-f]*|[0-9]+)$/i', $part) !== 1) {
                return null;
            }

            if (stripos($part, '0x') === 0) {
                $number = hexdec(substr($part, 2));
            } elseif (strlen($part) > 1 && $part[0] === '0') {
                if (preg_match('/^[0-7]+$/', $part) !== 1) {
                    return null;
                }

                $number = octdec($part);
            } else {
                $number = (int) $part;
            }

            $numbers[] = $number;
        }

        $last = array_pop($numbers);

        if ($last >= 256 ** (4 - count($numbers))) {
            return null;
        }

        foreach ($numbers as $number) {
            if ($number > 255) {
                return null;
            }
        }

        return (int) ($numbers === [] ? intdiv((int) $last, 256 ** 3) : $numbers[0]);
    }
}
