<?php

namespace Laravel\Passport\ClientMetadata;

/**
 * @internal
 */
final class Fetched
{
    /**
     * Create a new fetched document instance.
     *
     * @param  array<string, mixed>  $data  The validated document as it was published.
     */
    public function __construct(
        public readonly Document $document,
        public readonly int $lifetime,
        public readonly array $data = [],
    ) {
    }
}
