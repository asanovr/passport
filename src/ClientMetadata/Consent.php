<?php

namespace Laravel\Passport\ClientMetadata;

use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Contracts\Support\Jsonable;
use JsonSerializable;
use League\Uri\Uri;

/**
 * @implements \Illuminate\Contracts\Support\Arrayable<string, mixed>
 */
class Consent implements Arrayable, Jsonable, JsonSerializable
{
    /**
     * Create a new consent instance.
     */
    public function __construct(
        public string $url,
        public string $host,
        public string $name,
        public ?string $clientUri,
        public bool $clientUriMatchesOrigin,
        public ?string $logoUri,
        public bool $redirectIsLoopback,
        public bool $allRedirectsAreLoopback,
    ) {
    }

    /**
     * Create a new consent instance for the given document and the redirect address of the request.
     */
    public static function for(Document $document, ?string $redirectUri): static
    {
        $uri = Uri::new($document->url);

        return new static(
            $document->url,
            $uri->getHost(),
            $document->name,
            $document->clientUri,
            ! is_null($document->clientUri) && $uri->isSameOrigin($document->clientUri),
            $document->logoUri,
            ! is_null($redirectUri) && Loopback::isRedirect($redirectUri),
            collect($document->redirectUris)->every(fn (string $uri): bool => Loopback::isRedirect($uri)),
        );
    }

    /**
     * Get the instance as an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'url' => $this->url,
            'host' => $this->host,
            'name' => $this->name,
            'clientUri' => $this->clientUri,
            'clientUriMatchesOrigin' => $this->clientUriMatchesOrigin,
            'logoUri' => $this->logoUri,
            'redirectIsLoopback' => $this->redirectIsLoopback,
            'allRedirectsAreLoopback' => $this->allRedirectsAreLoopback,
        ];
    }

    /**
     * Convert the object into something JSON serializable.
     *
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * Convert the object to its JSON representation.
     *
     * @param  int  $options
     */
    public function toJson($options = 0): string
    {
        return json_encode($this->toArray(), $options);
    }
}
