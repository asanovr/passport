<?php

namespace Laravel\Passport\ClientMetadata;

/**
 * A validated Client ID Metadata Document.
 *
 * @internal
 */
final class Document
{
    /**
     * Create a new document instance.
     *
     * @param  string[]  $redirectUris
     */
    public function __construct(
        public readonly string $url,
        public readonly string $name,
        public readonly array $redirectUris,
        public readonly ?string $clientUri = null,
        public readonly ?string $logoUri = null,
    ) {
    }

    /**
     * Get the document as an array that can be cached.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'url' => $this->url,
            'name' => $this->name,
            'redirect_uris' => $this->redirectUris,
            'client_uri' => $this->clientUri,
            'logo_uri' => $this->logoUri,
        ];
    }

    /**
     * Create a document from the array it was cached as.
     *
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(array $data): static
    {
        return new static($data['url'], $data['name'], $data['redirect_uris'], $data['client_uri'], $data['logo_uri']);
    }
}
