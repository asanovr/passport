<?php

namespace Laravel\Passport\ClientMetadata;

use Laravel\Passport\Client;

/**
 * @internal
 */
class ResolvedClient
{
    /**
     * Create a new resolved client instance.
     */
    public function __construct(
        public readonly Client $client,
        public readonly Document $document,
    ) {
    }
}
