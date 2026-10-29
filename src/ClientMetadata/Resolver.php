<?php

namespace Laravel\Passport\ClientMetadata;

use Illuminate\Contracts\Cache\Lock;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\LockTimeoutException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Exceptions\AuthenticationException;
use Laravel\Passport\Exceptions\InvalidClientMetadataException;
use Laravel\Passport\Passport;
use Psr\Http\Message\ServerRequestInterface;

class Resolver
{
    /**
     * The number of seconds an address is not fetched again after a failed fetch.
     */
    protected const FAILURE_DELAY = 60;

    /**
     * Create a new resolver instance.
     */
    public function __construct(
        protected ClientRepository $clients,
        protected Fetcher $fetcher,
        protected DocumentValidator $validator,
    ) {
    }

    /**
     * Determine if the given client id is the address of a metadata document.
     */
    public static function isAddress(string $clientId): bool
    {
        return str_starts_with($clientId, 'https://');
    }

    /**
     * Resolve the client behind the given document address, fetching its document.
     *
     * @return array{0: \Laravel\Passport\Client, 1: \Laravel\Passport\ClientMetadata\Document}
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \Laravel\Passport\Exceptions\AuthenticationException
     */
    public function resolve(string $url, ServerRequestInterface $request, bool $authenticated): array
    {
        try {
            $address = Address::parse($url, Passport::$clientMetadataDocuments['allowPrivateNetworks']);
        } catch (UnusableDocumentException $e) {
            $this->refuse($request, $url, $e->getMessage());
        }

        $allowed = Passport::$clientMetadataDocuments['allowedHosts'];

        if (! empty($allowed) && ! Str::is(array_map(strtolower(...), $allowed), $address->host)) {
            $this->refuse($request, $url, 'The host is not in the list of allowed hosts.');
        }

        $existing = $this->clients->findByMetadataDocumentUrl($url);

        if ($existing?->revoked) {
            $this->refuse($request, $url, 'The client has been revoked.');
        }

        $document = $this->cached($url);

        if (is_null($document)) {
            $this->ensureMayFetch($request, $url, $authenticated);
        }

        if (is_null($existing) || is_null($document)) {
            return $this->resolveWhileLocked($request, $address, $authenticated);
        }

        return $this->store($request, $url, $document, $existing);
    }

    /**
     * Resolve the client behind the given document address while no other request resolves it.
     *
     * @return array{0: \Laravel\Passport\Client, 1: \Laravel\Passport\ClientMetadata\Document}
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \Laravel\Passport\Exceptions\AuthenticationException
     */
    protected function resolveWhileLocked(
        ServerRequestInterface $request,
        Address $address,
        bool $authenticated
    ): array {
        $url = $address->url;

        $resolve = function () use ($request, $address, $url, $authenticated): array {
            // The request that held the lock may have fetched the document, or failed to.
            $document = $this->cached($url);

            if (is_null($document)) {
                $this->ensureMayFetch($request, $url, $authenticated);

                $document = $this->fetch($request, $address);
            }

            // The record is looked up as late as possible: the request that held the lock may have created it.
            return $this->store($request, $url, $document, $this->clients->findByMetadataDocumentUrl($url));
        };

        $lock = $this->lock($url);

        if (is_null($lock)) {
            return $resolve();
        }

        $budget = Passport::$clientMetadataDocuments['connectTimeout'] + Passport::$clientMetadataDocuments['timeout'];

        try {
            // The lock gives up a quarter of a second before the seconds it is given, so we wait two extra seconds.
            return $lock->block($budget + 2, $resolve);
        } catch (LockTimeoutException) {
            $this->refuse($request, $url, 'Another fetch of the document did not finish in time.');
        }
    }

    /**
     * Refuse the request when the document of the given address may not be fetched for it.
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \Laravel\Passport\Exceptions\AuthenticationException
     */
    protected function ensureMayFetch(ServerRequestInterface $request, string $url, bool $authenticated): void
    {
        if (! $authenticated && Passport::$clientMetadataDocuments['requireAuthentication']) {
            throw new AuthenticationException;
        }

        if (Cache::has($this->key($url).':delayed')) {
            $this->refuse($request, $url, 'An earlier fetch failed and the next one is delayed.');
        }
    }

    /**
     * Store the client of the given document, or bring the existing one up to date.
     *
     * @return array{0: \Laravel\Passport\Client, 1: \Laravel\Passport\ClientMetadata\Document}
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    protected function store(
        ServerRequestInterface $request,
        string $url,
        Document $document,
        ?Client $existing
    ): array {
        try {
            $client = $this->clients->syncFromMetadataDocument($document, $existing);

            // Without a unique index, two requests that do not share a lock may both create a record, so
            // we will always settle on the oldest record for the address and remove the one we created.
            if ($client->wasRecentlyCreated) {
                $chosen = $this->clients->findByMetadataDocumentUrl($url);

                if (! is_null($chosen) && ! $chosen->is($client)) {
                    $client->delete();

                    $client = $this->clients->syncFromMetadataDocument($document, $chosen);
                }
            }
        } catch (UnusableDocumentException $e) {
            $this->refuse($request, $url, $e->getMessage());
        }

        if ($client->revoked) {
            $this->refuse($request, $url, 'The client has been revoked.');
        }

        return [$client, $document];
    }

    /**
     * Fetch the document at the given address, and keep it for as long as it is fresh.
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    protected function fetch(ServerRequestInterface $request, Address $address): Document
    {
        $url = $address->url;

        try {
            ['data' => $data, 'lifetime' => $lifetime] = $this->fetcher->fetch($address);

            $document = $this->validator->validate($address, $data);
        } catch (UnusableDocumentException $e) {
            Cache::add($this->key($url).':delayed', true, static::FAILURE_DELAY);

            $this->refuse($request, $url, $e->getMessage());
        }

        Cache::put($this->documentKey($url), get_object_vars($document), $lifetime);

        return $document;
    }

    /**
     * Get the validated document that is cached for the given address.
     */
    protected function cached(string $url): ?Document
    {
        $cached = Cache::get($this->documentKey($url));

        return is_array($cached) ? new Document(...$cached) : null;
    }

    /**
     * Get a lock that serialises the resolving of the given address, if the cache store has atomic locks.
     */
    protected function lock(string $url): ?Lock
    {
        if (! Cache::getStore() instanceof LockProvider) {
            return null;
        }

        $budget = Passport::$clientMetadataDocuments['connectTimeout'] + Passport::$clientMetadataDocuments['timeout'];

        return Cache::lock($this->key($url).':lock', $budget + 5);
    }

    /**
     * Get the cache key of the validated document of the given address.
     */
    protected function documentKey(string $url): string
    {
        return $this->key($url).':document:v1:'.(int) Passport::$clientMetadataDocuments['allowLoopbackRedirects'].
            (int) Passport::$clientMetadataDocuments['allowPrivateNetworks'];
    }

    /**
     * Get the cache key of the given address.
     */
    protected function key(string $url): string
    {
        return 'passport:client-metadata:'.hash('sha256', $url);
    }

    /**
     * Log why the document cannot be used and refuse the client.
     */
    protected function refuse(ServerRequestInterface $request, string $url, string $reason): never
    {
        Log::warning('Client metadata document refused.', [
            'reason' => $reason,
            'host' => parse_url($url, PHP_URL_HOST) ?: null,
        ]);

        throw InvalidClientMetadataException::unusable($request);
    }
}
