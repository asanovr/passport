<?php

namespace Laravel\Passport\ClientMetadata;

/**
 * @internal
 */
final class Fetched
{
    /**
     * Create a new fetched document instance.
     */
    public function __construct(
        public readonly Document $document,
        public readonly int $lifetime,
    ) {
    }
}
