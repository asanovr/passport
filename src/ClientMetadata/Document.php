<?php

namespace Laravel\Passport\ClientMetadata;

/**
 * A validated Client ID Metadata Document.
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
}
