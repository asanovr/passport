<?php

namespace Laravel\Passport\ClientMetadata;

use Closure;
use Illuminate\Contracts\Cache\LockTimeoutException;
use Illuminate\Support\Facades\Log;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Exceptions\InvalidClientMetadataException;
use Laravel\Passport\Passport;
use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Resolves a client id that is the address of a Client ID Metadata Document.
 *
 * @internal
 */
class Resolver
{
    /**
     * Create a new resolver instance.
     */
    public function __construct(
        protected ClientRepository $clients,
        protected Fetcher $fetcher,
        protected DocumentCache $cache,
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
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \Laravel\Passport\ClientMetadata\SignInRequiredException
     */
    public function resolve(string $url, ServerRequestInterface $request, bool $authenticated): ResolvedClient
    {
        // An application that does not accept metadata documents answers as it always has.
        if (! Passport::clientMetadataDocumentsEnabled()) {
            throw OAuthServerException::invalidClient($request);
        }

        try {
            $address = Address::parse($url, Passport::$clientMetadataConfiguration->allowPrivateNetworks);
        } catch (UnusableDocumentException $e) {
            $this->refuse($request, $url, $e->getMessage());
        }

        if (! $this->isAllowed($address->host)) {
            $this->refuse($request, $url, 'the host is not in the list of allowed hosts');
        }

        $existing = $this->clients->findByMetadataDocumentUrl($url);

        if ($existing?->revoked) {
            $this->refuse($request, $url, 'the client has been revoked');
        }

        $document = $this->cache->get($url);

        if ($document === null) {
            $this->ensureDocumentMayBeFetched($request, $url, $authenticated);
        }

        // Only a client that exists, with a document that is fresh, is brought up to date without the lock.
        if ($existing === null || $document === null) {
            return $this->resolveWhileLocked($request, $address, $authenticated);
        }

        return $this->store($request, $url, $document, $existing);
    }

    /**
     * Resolve the client behind the given document address while no other request resolves it.
     *
     * The lock covers the fetch and the write of the record, which is what keeps one record per address.
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \Laravel\Passport\ClientMetadata\SignInRequiredException
     */
    protected function resolveWhileLocked(ServerRequestInterface $request, Address $address, bool $authenticated): ResolvedClient
    {
        $url = $address->url;
        $configuration = Passport::$clientMetadataConfiguration;

        $lock = $this->cache->lock($url);

        try {
            // The wait covers everything the request that holds the lock may spend on its fetch and its write. The
            // lock gives up a quarter of a second before the seconds it is given, so two extra seconds leave at least
            // one spare.
            $lock?->block($configuration->connectTimeout + $configuration->timeout + 2);
        } catch (LockTimeoutException) {
            $this->refuse($request, $url, 'another fetch of the document did not finish in time');
        }

        try {
            // The request that held the lock may have fetched the document, or failed to.
            $document = $this->cache->get($url);

            if ($document === null) {
                $this->ensureDocumentMayBeFetched($request, $url, $authenticated);

                $document = $this->fetch($request, $address);
            }

            // The record is looked up as late as possible: the request that held the lock may have created it.
            $existing = $this->clients->findByMetadataDocumentUrl($url);

            return $this->store($request, $url, $document, $existing);
        } finally {
            $lock?->release();
        }
    }

    /**
     * Refuse the request when the document of the given address may not be fetched for it.
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \Laravel\Passport\ClientMetadata\SignInRequiredException
     */
    protected function ensureDocumentMayBeFetched(ServerRequestInterface $request, string $url, bool $authenticated): void
    {
        // Nobody who is not signed in can make the server fetch a document.
        if (! $authenticated && Passport::$clientMetadataConfiguration->requireAuthentication) {
            throw new SignInRequiredException;
        }

        if ($this->cache->isDelayed($url)) {
            $this->refuse($request, $url, 'an earlier fetch failed and the next one is delayed');
        }
    }

    /**
     * Store the client of the given document, or bring the existing one up to date.
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    protected function store(ServerRequestInterface $request, string $url, Document $document, ?Client $existing): ResolvedClient
    {
        if ($existing?->revoked) {
            $this->refuse($request, $url, 'the client has been revoked');
        }

        try {
            $client = $this->clients->syncFromMetadataDocument($document, $existing);

            // Without a unique index, a request that does not share a lock may have created a record as well.
            // Every request settles on the oldest one, so the newcomer yields to it.
            if ($client->wasRecentlyCreated) {
                $chosen = $this->clients->findByMetadataDocumentUrl($url);

                if ($chosen !== null && ! $chosen->is($client)) {
                    $client->delete();

                    if ($chosen->revoked) {
                        $this->refuse($request, $url, 'the client has been revoked');
                    }

                    $client = $this->clients->syncFromMetadataDocument($document, $chosen);
                }
            }
        } catch (UnusableDocumentException $e) {
            $this->refuse($request, $url, $e->getMessage());
        }

        if ($client->revoked) {
            $this->refuse($request, $url, 'the client has been revoked');
        }

        return new ResolvedClient($client, $document);
    }

    /**
     * Determine if documents may be fetched from the given host.
     */
    protected function isAllowed(string $host): bool
    {
        $allowed = Passport::$clientMetadataConfiguration->allowedHosts;

        if ($allowed === []) {
            return true;
        }

        $host = strtolower($host);

        foreach ($allowed as $pattern) {
            $pattern = strtolower($pattern);

            if ($host === $pattern || (str_starts_with($pattern, '*.') && str_ends_with($host, substr($pattern, 1)))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Let the application refuse a document that Passport has validated.
     *
     * @throws \Laravel\Passport\ClientMetadata\UnusableDocumentException
     */
    protected function applyValidationHook(FetchedDocument $fetched, string $url): void
    {
        if (! Passport::$clientMetadataDocumentValidator instanceof Closure) {
            return;
        }

        $reason = (Passport::$clientMetadataDocumentValidator)($fetched->data, $url);

        if (is_string($reason) && $reason !== '') {
            throw new UnusableDocumentException("the application refused the document: {$reason}");
        }
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
            $fetched = $this->fetcher->fetch($address);

            $this->applyValidationHook($fetched, $url);
        } catch (UnusableDocumentException $e) {
            $this->cache->recordFailure($url);

            $this->refuse($request, $url, $e->getMessage());
        }

        $this->cache->put($fetched->document, $fetched->lifetime);
        $this->cache->forgetFailures($url);

        return $fetched->document;
    }

    /**
     * Log why the document cannot be used and refuse the client.
     */
    protected function refuse(ServerRequestInterface $request, string $url, string $reason): never
    {
        Log::warning("Client metadata document refused: {$reason}.", [
            'host' => parse_url($url, PHP_URL_HOST) ?: null,
        ]);

        throw InvalidClientMetadataException::unusable($request);
    }
}
