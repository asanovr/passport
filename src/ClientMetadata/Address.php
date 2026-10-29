<?php

namespace Laravel\Passport\ClientMetadata;

use GuzzleHttp\Psr7\Exception\MalformedUriException;
use GuzzleHttp\Psr7\Uri;
use League\Uri\Exceptions\SyntaxError;
use League\Uri\HostRecord;
use League\Uri\UriString;

class Address
{
    /**
     * Create a new address instance.
     */
    protected function __construct(
        public string $url,
        public string $host,
    ) {
    }

    /**
     * Parse the given client id, which starts with "https://".
     *
     * @throws \Laravel\Passport\ClientMetadata\UnusableDocumentException
     */
    public static function parse(string $url, bool $allowPort = false): static
    {
        if (strlen($url) > 255) {
            throw new UnusableDocumentException('The address is longer than 255 bytes.');
        }

        if (! UriString::containsRfc3986Chars($url)) {
            throw new UnusableDocumentException('The address contains a character that a URI may not contain.');
        }

        try {
            $parts = UriString::parse($url);
            $guzzle = new Uri($url);
        } catch (SyntaxError|MalformedUriException) {
            throw new UnusableDocumentException('The address is malformed.');
        }

        if (! is_null($parts['user'])) {
            throw new UnusableDocumentException('The address has user information.');
        }

        if (! $allowPort && ! is_null($parts['port'])) {
            throw new UnusableDocumentException('The address has a port.');
        }

        if (! static::isValidHost($guzzle->getHost())) {
            throw new UnusableDocumentException('The address has an invalid host.');
        }

        if (! is_null($parts['fragment'])) {
            throw new UnusableDocumentException('The address has a fragment.');
        }

        if (! is_null($parts['query'])) {
            throw new UnusableDocumentException('The address has a query.');
        }

        if (in_array($parts['path'], ['', '/'])) {
            throw new UnusableDocumentException('The address has no path.');
        }

        foreach (explode('/', $parts['path']) as $segment) {
            if (in_array(rawurldecode($segment), ['.', '..'])) {
                throw new UnusableDocumentException('The address has a dot segment.');
            }
        }

        return new static($url, $guzzle->getHost());
    }

    /**
     * Determine if the given host is a DNS name or an IP address.
     */
    protected static function isValidHost(string $host): bool
    {
        if (HostRecord::isIpv4($host)) {
            return true;
        }

        // A zone id (a "%" in an IPv6 address) names a network interface of this machine, not a host.
        if (HostRecord::isIpv6($host)) {
            return ! str_contains($host, '%');
        }

        // League also accepts a percent-encoded host, which it decodes, a trailing dot, and a host made only of
        // numbers, which the transport reads as an address in a form that no address is written in ("127.1").
        return HostRecord::isDomain($host) && ! str_contains($host, '%') && ! str_ends_with($host, '.') &&
            preg_match('/^(\d+|0x[0-9a-f]*)(\.(\d+|0x[0-9a-f]*))*$/Di', $host) !== 1;
    }
}
