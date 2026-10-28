<?php

namespace Laravel\Passport\ClientMetadata;

use InvalidArgumentException;

/**
 * @internal
 */
class Configuration
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
        foreach (compact(
            'connectTimeout', 'timeout', 'maximumSize', 'defaultLifetime', 'minimumLifetime', 'maximumLifetime'
        ) as $name => $value) {
            if ($value < 1) {
                throw new InvalidArgumentException("The client metadata document option [{$name}] must be at least 1.");
            }
        }

        if ($minimumLifetime > $maximumLifetime) {
            throw new InvalidArgumentException(
                'The minimum lifetime of a client metadata document must not be greater than its maximum lifetime.'
            );
        }
    }
}
