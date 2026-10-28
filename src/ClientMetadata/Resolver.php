<?php

namespace Laravel\Passport\ClientMetadata;

use Illuminate\Contracts\Cache\LockTimeoutException;
use Illuminate\Support\Facades\Log;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Exceptions\InvalidClientMetadataException;
use Laravel\Passport\Passport;
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
        protected Cache $cache,
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
     */
    public function resolve(string $url, ServerRequestInterface $request): ResolvedClient
    {
        if (! Passport::clientMetadataDocumentsEnabled()) {
            $this->refuse($request, $url, 'client metadata documents are not enabled');
        }

        try {
            $address = Address::parse($url, Passport::$clientMetadataConfiguration->allowPrivateNetworks);
        } catch (UnusableDocumentException $e) {
            $this->refuse($request, $url, $e->getMessage());
        }

        $existing = $this->clients->findByMetadataDocumentUrl($url);

        if ($existing?->revoked) {
            $this->refuse($request, $url, 'the client has been revoked');
        }

        $document = $this->cache->get($url) ?? $this->fetch($request, $address);

        $client = $this->clients->syncFromMetadataDocument($document, $existing);

        if ($client->revoked) {
            $this->refuse($request, $url, 'the client has been revoked');
        }

        return new ResolvedClient($client, $document);
    }

    /**
     * Fetch the document at the given address, unless another request is fetching it.
     */
    protected function fetch(ServerRequestInterface $request, Address $address): Document
    {
        $url = $address->url;

        if ($this->cache->isDelayed($url)) {
            $this->refuse($request, $url, 'an earlier fetch failed and the next one is delayed');
        }

        $lock = $this->cache->lock($url);

        try {
            $lock->block(Passport::$clientMetadataConfiguration->timeout);
        } catch (LockTimeoutException) {
            $this->refuse($request, $url, 'another fetch of the document did not finish in time');
        }

        try {
            // The request that held the lock may have fetched the document, or failed to.
            if ($document = $this->cache->get($url)) {
                return $document;
            }

            if ($this->cache->isDelayed($url)) {
                $this->refuse($request, $url, 'an earlier fetch failed and the next one is delayed');
            }

            try {
                $fetched = $this->fetcher->fetch($address);
            } catch (UnusableDocumentException $e) {
                $this->cache->recordFailure($url);

                $this->refuse($request, $url, $e->getMessage());
            }

            $this->cache->put($fetched->document, $fetched->lifetime);
            $this->cache->forgetFailures($url);

            return $fetched->document;
        } finally {
            $lock->release();
        }
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
