<?php

namespace Laravel\Passport\ClientMetadata;

/**
 * @internal
 */
class FetchedDocument
{
    /**
     * Create a new fetched document instance.
     *
     * @param  array<string, mixed>  $data  The validated document as it was published.
     */
    public function __construct(
        public readonly Document $document,
        public readonly int $lifetime,
        public readonly array $data,
    ) {
    }
}
