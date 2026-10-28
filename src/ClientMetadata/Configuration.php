<?php

namespace Laravel\Passport\ClientMetadata;

/**
 * @internal
 */
final class Configuration
{
    /**
     * Create a new configuration instance.
     *
     * @param  string[]  $allowedHosts
     */
    public function __construct(
        public readonly bool $requireAuthentication = true,
        public readonly array $allowedHosts = [],
        public readonly bool $allowLoopbackRedirects = true,
        public readonly bool $allowPrivateNetworks = false,
        public readonly ?string $proxy = null,
        public readonly int $connectTimeout = 2,
        public readonly int $timeout = 3,
        public readonly int $maximumSize = 5120,
        public readonly int $defaultLifetime = 600,
        public readonly int $minimumLifetime = 60,
        public readonly int $maximumLifetime = 86400,
    ) {
    }
}
