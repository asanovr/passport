<?php

namespace Laravel\Passport\ClientMetadata;

/**
 * @internal
 */
final class Configuration
{
    /**
     * Create a new configuration instance.
     */
    public function __construct(
        public readonly bool $allowPrivateNetworks = false,
        public readonly int $connectTimeout = 2,
        public readonly int $timeout = 3,
        public readonly int $maximumSize = 5120,
    ) {
    }
}
