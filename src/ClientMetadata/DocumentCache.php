<?php

namespace Laravel\Passport\ClientMetadata;

use Illuminate\Contracts\Cache\Lock;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Support\Facades\Cache as Store;
use Illuminate\Support\Facades\Date;
use Laravel\Passport\Passport;

/**
 * Keeps validated documents, the delays after failed fetches and the locks that serialise fetches.
 *
 * @internal
 */
class DocumentCache
{
    /**
     * The delay after the first failed fetch of an address, in seconds.
     */
    protected const FIRST_DELAY = 30;

    /**
     * The longest delay after failed fetches of an address, in seconds.
     */
    protected const LONGEST_DELAY = 600;

    /**
     * Get the validated document cached for the given address.
     */
    public function get(string $url): ?Document
    {
        $data = Store::get($this->documentKey($url));

        return is_array($data) ? Document::fromArray($data) : null;
    }

    /**
     * Cache the validated document for the given number of seconds.
     */
    public function put(Document $document, int $lifetime): void
    {
        Store::put($this->documentKey($document->url), $document->toArray(), $lifetime);
    }

    /**
     * Get a lock that serialises the fetches of the given address, if the cache store has atomic locks.
     */
    public function lock(string $url): ?Lock
    {
        if (! Store::getStore() instanceof LockProvider) {
            return null;
        }

        $configuration = Passport::$clientMetadataConfiguration;

        return Store::lock($this->key($url).':lock', $configuration->connectTimeout + $configuration->timeout + 5);
    }

    /**
     * Determine if fetching the given address is still delayed by earlier failures.
     */
    public function isDelayed(string $url): bool
    {
        $state = Store::get($this->key($url).':failures');

        return is_array($state) && $state['until'] > Date::now()->getTimestamp();
    }

    /**
     * Record a failed fetch of the given address, which doubles the delay before the next one.
     */
    public function recordFailure(string $url): void
    {
        $key = $this->key($url).':failures';

        $failures = (Store::get($key)['failures'] ?? 0) + 1;

        $delay = min(static::FIRST_DELAY * (2 ** ($failures - 1)), static::LONGEST_DELAY);

        Store::put($key, [
            'failures' => $failures,
            'until' => Date::now()->getTimestamp() + $delay,
        ], $delay + static::LONGEST_DELAY);
    }

    /**
     * Forget the failed fetches of the given address.
     */
    public function forgetFailures(string $url): void
    {
        Store::forget($this->key($url).':failures');
    }

    /**
     * Get the cache key of the validated document of the given address.
     *
     * The key carries the settings that decide whether a document is valid, so that a document
     * that was validated under other settings is never used.
     */
    protected function documentKey(string $url): string
    {
        $configuration = Passport::$clientMetadataConfiguration;

        return $this->key($url).':document:v1:'.hash('xxh128', json_encode([
            $configuration->allowLoopbackRedirects,
            $configuration->allowPrivateNetworks,
        ]));
    }

    /**
     * Get the cache key of the given address.
     */
    protected function key(string $url): string
    {
        return 'passport:client-metadata:'.hash('sha256', $url);
    }
}
