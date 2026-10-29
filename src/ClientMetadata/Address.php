<?php

namespace Laravel\Passport\ClientMetadata;

use GuzzleHttp\Psr7\Exception\MalformedUriException;
use GuzzleHttp\Psr7\Uri;
use League\Uri\Exceptions\SyntaxError;
use League\Uri\HostRecord;
use League\Uri\UriString;

/**
 * The address of a Client ID Metadata Document.
 *
 * An address is parsed once, strictly, and the host that is vetted is the host the HTTP client connects to.
 */
class Address
{
    /**
     * Create a new address instance.
     */
    private function __construct(
        public readonly string $url,
        public readonly string $host,
    ) {
    }

    /**
     * Parse the given client id, which starts with "https://".
     *
     * @throws \Laravel\Passport\ClientMetadata\UnusableDocumentException
     */
    public static function parse(string $url, bool $allowPort = false): self
    {
        if (strlen($url) > 255) {
            throw new UnusableDocumentException('the address is longer than 255 bytes');
        }

        if (! UriString::containsRfc3986Chars($url)) {
            throw new UnusableDocumentException('the address contains a character that a URI may not contain');
        }

        try {
            $parts = UriString::parse($url);
            $guzzle = new Uri($url);
        } catch (SyntaxError|MalformedUriException) {
            throw new UnusableDocumentException('the address is malformed');
        }

        if ($parts['user'] !== null) {
            throw new UnusableDocumentException('the address has user information');
        }

        if (! $allowPort && $parts['port'] !== null) {
            throw new UnusableDocumentException('the address has a port');
        }

        // The fetch is the HTTP client's, so the host it connects to is the host that is vetted.
        if (! static::isValidHost($guzzle->getHost())) {
            throw new UnusableDocumentException('the address has an invalid host');
        }

        if ($parts['fragment'] !== null) {
            throw new UnusableDocumentException('the address has a fragment');
        }

        if ($parts['query'] !== null) {
            throw new UnusableDocumentException('the address has a query');
        }

        if (in_array($parts['path'], ['', '/'], true)) {
            throw new UnusableDocumentException('the address has no path');
        }

        foreach (explode('/', $parts['path']) as $segment) {
            if (in_array(rawurldecode($segment), ['.', '..'], true)) {
                throw new UnusableDocumentException('the address has a dot segment');
            }
        }

        return new self($url, $guzzle->getHost());
    }

    /**
     * Determine if the given host is a DNS name or an IP address.
     *
     * Only these hosts are fetched, so that the host that is vetted is the host the connection is made to,
     * whichever way a URI parser or the transport reads an unusual one.
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
