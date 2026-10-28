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
final class Address
{
    /**
     * Create a new address instance.
     */
    protected function __construct(
        public readonly string $url,
        public readonly string $host,
    ) {
    }

    /**
     * Parse the given client id, which starts with "https://".
     *
     * @throws \Laravel\Passport\ClientMetadata\UnusableDocumentException
     */
    public static function parse(string $url, bool $allowPort = false): static
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

        return new static($url, $uri->getHost());
    }
}
