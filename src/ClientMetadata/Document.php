<?php

namespace Laravel\Passport\ClientMetadata;

class Document
{
    /**
     * Create a new document instance.
     *
     * @param  string[]  $redirectUris
     */
    public function __construct(
        public string $url,
        public string $name,
        public array $redirectUris,
        public ?string $clientUri = null,
        public ?string $logoUri = null,
    ) {
    }
}
