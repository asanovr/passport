<?php

namespace Laravel\Passport\ClientMetadata;

/**
 * A validated Client ID Metadata Document.
 *
 * @internal
 */
class Document
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
     * Create a document from the array it was cached as, or null if the array is not of that shape.
     *
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(array $data): ?static
    {
        $redirectUris = $data['redirect_uris'] ?? null;

        if (! is_string($data['url'] ?? null) ||
            ! is_string($data['name'] ?? null) ||
            ! is_array($redirectUris) || array_filter($redirectUris, is_string(...)) !== $redirectUris) {
            return null;
        }

        foreach (['client_uri', 'logo_uri'] as $key) {
            if (! array_key_exists($key, $data) || ($data[$key] !== null && ! is_string($data[$key]))) {
                return null;
            }
        }

        return new static($data['url'], $data['name'], $data['redirect_uris'], $data['client_uri'], $data['logo_uri']);
    }
}
