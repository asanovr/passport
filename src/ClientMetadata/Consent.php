<?php

namespace Laravel\Passport\ClientMetadata;

use GuzzleHttp\Psr7\Exception\MalformedUriException;
use GuzzleHttp\Psr7\Uri;
use JsonSerializable;

/**
 * What the authorization view knows about a client that is identified by a metadata document.
 */
class Consent implements JsonSerializable
{
    /**
     * Create a new consent value instance.
     *
     * @param  string  $url  The address of the client's metadata document, which is its client id.
     * @param  string  $host  The host that publishes the document.
     * @param  string  $name  The client's name, or the host when the document has none.
     * @param  string|null  $clientUri  The client's website as published, if any.
     * @param  bool  $clientUriMatchesOrigin  Whether the website has the same origin as the document; false when there is none.
     * @param  string|null  $logoUri  The address of the client's logo as published, if any. Never hotlink it blindly.
     * @param  bool  $redirectIsLoopback  Whether the redirect address of this request is on a loopback host.
     * @param  bool  $allRedirectsAreLoopback  Whether every redirect address the document lists is on a loopback host.
     */
    public function __construct(
        public readonly string $url,
        public readonly string $host,
        public readonly string $name,
        public readonly ?string $clientUri,
        public readonly bool $clientUriMatchesOrigin,
        public readonly ?string $logoUri,
        public readonly bool $redirectIsLoopback,
        public readonly bool $allRedirectsAreLoopback,
    ) {
    }

    /**
     * Create the value for the given document and the redirect address of the request.
     *
     * @internal
     */
    public static function for(Document $document, ?string $redirectUri): static
    {
        $host = parse_url($document->url, PHP_URL_HOST);

        return new static(
            $document->url,
            $host,
            $document->name,
            $document->clientUri,
            $document->clientUri !== null && static::origin($document->clientUri) === static::origin($document->url),
            $document->logoUri,
            $redirectUri !== null && Loopback::isRedirect($redirectUri),
            array_filter($document->redirectUris, fn (string $uri): bool => ! Loopback::isRedirect($uri)) === [],
        );
    }

    /**
     * Get the origin (scheme, host and port) of the given address.
     */
    protected static function origin(string $url): ?string
    {
        try {
            $uri = new Uri($url);
        } catch (MalformedUriException) {
            return null;
        }

        return $uri->getScheme().'://'.$uri->getHost().':'.($uri->getPort() ?? 443);
    }

    /**
     * Get the value as an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return get_object_vars($this);
    }

    /**
     * Get the data that should be serialized to JSON.
     *
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
