<?php

namespace Laravel\Passport\ClientMetadata;

use GuzzleHttp\Psr7\Exception\MalformedUriException;
use GuzzleHttp\Psr7\Uri;
use League\Uri\Exceptions\SyntaxError;
use League\Uri\UriString;

/**
 * The address of a Client ID Metadata Document.
 *
 * An address is parsed once, strictly, and read the same way by the parser the HTTP client uses.
 */
class Address
{
    /**
     * Create a new address instance.
     */
    private function __construct(
        public readonly string $url,
        public readonly string $host,
        public readonly int $port = 443,
    ) {
    }

    /**
     * Parse the given client id, which starts with "https://".
     *
     * @throws \Laravel\Passport\ClientMetadata\UnusableDocumentException
     */
    public static function parse(string $url, bool $allowPort = false): self
    {
        if (! str_starts_with($url, 'https://')) {
            throw new UnusableDocumentException('the address is not an https address');
        }

        if (strlen($url) > 255) {
            throw new UnusableDocumentException('the address is longer than 255 bytes');
        }

        if (preg_match('/^[\x21-\x7e]+$/D', $url) !== 1) {
            throw new UnusableDocumentException('the address contains a space, control or non-ASCII character');
        }

        if (str_contains($url, '\\')) {
            throw new UnusableDocumentException('the address contains a backslash');
        }

        try {
            $parts = UriString::parse($url);
            $guzzle = new Uri($url);
        } catch (SyntaxError|MalformedUriException) {
            throw new UnusableDocumentException('the address is malformed');
        }

        $host = (string) $parts['host'];

        if ($host === '') {
            throw new UnusableDocumentException('the address has no host');
        }

        if ($parts['user'] !== null) {
            throw new UnusableDocumentException('the address has user information');
        }

        // An empty port ("host:") is read as no port, so it is found in the address itself.
        if (! $allowPort && ($parts['port'] !== null || str_starts_with(substr($url, 8), $host.':'))) {
            throw new UnusableDocumentException('the address has a port');
        }

        if (! static::isValidHost($host)) {
            throw new UnusableDocumentException('the address has an invalid host');
        }

        // The fetch is the HTTP client's, so it has to read the same host and port.
        if ($guzzle->getHost() !== strtolower($host) || ($guzzle->getPort() ?? 443) !== ($parts['port'] ?? 443)) {
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

        return new self($url, $guzzle->getHost(), $parts['port'] ?? 443);
    }

    /**
     * Determine if the given host is a DNS name or an IP address.
     *
     * Only these hosts are fetched, so that the host that is vetted is the host the connection is made to,
     * whichever way a URI parser or the transport reads an unusual one.
     */
    protected static function isValidHost(string $host): bool
    {
        if (str_starts_with($host, '[')) {
            return filter_var(substr($host, 1, -1), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
        }

        // A host made only of numbers is read as an address by the transport, so it has to be one.
        if (preg_match('/^(\d+|0x[0-9a-f]*)(\.(\d+|0x[0-9a-f]*))*$/Di', $host) === 1) {
            return filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
        }

        return ! str_ends_with($host, '.') && filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false;
    }
}
