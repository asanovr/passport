<?php

namespace Laravel\Passport\ClientMetadata;

use GuzzleHttp\Psr7\Exception\MalformedUriException;
use GuzzleHttp\Psr7\Uri;

/**
 * The address of a Client ID Metadata Document.
 *
 * An address is parsed once, strictly, and with the parser the HTTP client uses.
 *
 * @internal
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
            $uri = new Uri($url);
        } catch (MalformedUriException) {
            throw new UnusableDocumentException('the address is malformed');
        }

        if ($uri->getHost() === '') {
            throw new UnusableDocumentException('the address has no host');
        }

        // The parser drops the default port, so the authority is read from the address itself.
        $authority = explode('/', preg_split('/[?#]/', substr($url, 8), 2)[0], 2)[0];

        if (str_contains($authority, '@') || $uri->getUserInfo() !== '') {
            throw new UnusableDocumentException('the address has user information');
        }

        $hostPart = str_starts_with($authority, '[') ? substr($authority, (int) strpos($authority, ']')) : $authority;

        if (! $allowPort && str_contains($hostPart, ':')) {
            throw new UnusableDocumentException('the address has a port');
        }

        $host = str_starts_with($authority, '[')
            ? substr($authority, 0, (int) strpos($authority, ']') + 1)
            : explode(':', $authority)[0];

        if (! static::isValidHost($host, $uri->getHost())) {
            throw new UnusableDocumentException('the address has an invalid host');
        }

        if (str_contains($url, '#')) {
            throw new UnusableDocumentException('the address has a fragment');
        }

        if (str_contains($url, '?')) {
            throw new UnusableDocumentException('the address has a query');
        }

        if (in_array($uri->getPath(), ['', '/'], true)) {
            throw new UnusableDocumentException('the address has no path');
        }

        foreach (explode('/', $uri->getPath()) as $segment) {
            if (in_array(rawurldecode($segment), ['.', '..'], true)) {
                throw new UnusableDocumentException('the address has a dot segment');
            }
        }

        return new self($url, $uri->getHost(), $uri->getPort() ?? 443);
    }

    /**
     * Determine if the given host, as written in the address, is a DNS name or an IP address that the parser read as is.
     *
     * Only these hosts are fetched, so that the host that is vetted is the host the connection is made to,
     * whichever way a URI parser or the transport reads an unusual one.
     */
    protected static function isValidHost(string $host, string $parsed): bool
    {
        if (strtolower($host) !== $parsed) {
            return false;
        }

        if (str_starts_with($host, '[')) {
            return str_ends_with($host, ']') &&
                filter_var(substr($host, 1, -1), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
        }

        $labels = explode('.', $host);

        foreach ($labels as $label) {
            if (preg_match('/^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/D', $label) !== 1) {
                return false;
            }
        }

        // A host made only of numbers is read as an address by the transport, so it has to be one.
        $numbers = array_filter($labels, fn (string $label): bool => preg_match('/^(\d+|0x[0-9a-f]*)$/i', $label) === 1);

        if (count($numbers) === count($labels)) {
            return filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
        }

        return true;
    }
}
