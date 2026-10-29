<?php

namespace Laravel\Passport\ClientMetadata;

use Closure;
use Illuminate\Contracts\Cache\Lock;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\LockTimeoutException;
use Illuminate\Contracts\Validation\Factory as ValidationFactory;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Exceptions\AuthenticationException;
use Laravel\Passport\Exceptions\InvalidClientMetadataException;
use Laravel\Passport\Passport;
use League\Uri\Exceptions\SyntaxError;
use League\Uri\UriString;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Resolves a client id that is the address of a Client ID Metadata Document.
 */
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
        protected ValidationFactory $validation,
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

        if ($allowed !== [] && ! Str::is(array_map('strtolower', $allowed), strtolower($address->host))) {
            $this->refuse($request, $url, 'the host is not in the list of allowed hosts');
        }

        $existing = $this->clients->findByMetadataDocumentUrl($url);

        if ($existing?->revoked) {
            $this->refuse($request, $url, 'the client has been revoked');
        }

        $document = $this->cached($url);

        if ($document === null) {
            $this->ensureMayFetch($request, $url, $authenticated);
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
     * @return array{0: \Laravel\Passport\Client, 1: \Laravel\Passport\ClientMetadata\Document}
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \Laravel\Passport\Exceptions\AuthenticationException
     */
    protected function resolveWhileLocked(ServerRequestInterface $request, Address $address, bool $authenticated): array
    {
        $url = $address->url;

        $resolve = function () use ($request, $address, $authenticated): array {
            // The request that held the lock may have fetched the document, or failed to.
            $document = $this->cached($address->url);

            if ($document === null) {
                $this->ensureMayFetch($request, $address->url, $authenticated);

                $document = $this->fetch($request, $address);
            }

            // The record is looked up as late as possible: the request that held the lock may have created it.
            return $this->store($request, $address->url, $document, $this->clients->findByMetadataDocumentUrl($address->url));
        };

        $lock = $this->lock($url);

        if ($lock === null) {
            return $resolve();
        }

        try {
            // The wait covers everything the request that holds the lock may spend on its fetch and its write. The
            // lock gives up a quarter of a second before the seconds it is given, so two extra seconds leave at least
            // one spare.
            return $lock->block(
                Passport::$clientMetadataDocuments['connectTimeout'] + Passport::$clientMetadataDocuments['timeout'] + 2, $resolve
            );
        } catch (LockTimeoutException) {
            $this->refuse($request, $url, 'another fetch of the document did not finish in time');
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
        // Nobody who is not signed in can make the server fetch a document.
        if (! $authenticated && Passport::$clientMetadataDocuments['requireAuthentication']) {
            throw new AuthenticationException;
        }

        if (Cache::has($this->key($url).':delayed')) {
            $this->refuse($request, $url, 'an earlier fetch failed and the next one is delayed');
        }
    }

    /**
     * Store the client of the given document, or bring the existing one up to date.
     *
     * @return array{0: \Laravel\Passport\Client, 1: \Laravel\Passport\ClientMetadata\Document}
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    protected function store(ServerRequestInterface $request, string $url, Document $document, ?Client $existing): array
    {
        try {
            $client = $this->clients->syncFromMetadataDocument($document, $existing);

            // Without a unique index, a request that does not share a lock may have created a record as well.
            // Every request settles on the oldest one, so the newcomer yields to it.
            if ($client->wasRecentlyCreated) {
                $chosen = $this->clients->findByMetadataDocumentUrl($url);

                if ($chosen !== null && ! $chosen->is($client)) {
                    $client->delete();

                    $client = $this->clients->syncFromMetadataDocument($document, $chosen);
                }
            }
        } catch (UnusableDocumentException $e) {
            $this->refuse($request, $url, $e->getMessage());
        }

        if ($client->revoked) {
            $this->refuse($request, $url, 'the client has been revoked');
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
            [$data, $lifetime] = $this->fetcher->fetch($address);

            $document = $this->validate($address, $data);

            $this->applyValidationHook($data, $url);
        } catch (UnusableDocumentException $e) {
            Cache::add($this->key($url).':delayed', true, static::FAILURE_DELAY);

            $this->refuse($request, $url, $e->getMessage());
        }

        Cache::put($this->documentKey($url), get_object_vars($document), $lifetime);

        return $document;
    }

    /**
     * Validate the decoded document published at the given address.
     *
     * @param  array<string, mixed>  $data
     *
     * @throws \Laravel\Passport\ClientMetadata\UnusableDocumentException
     */
    protected function validate(Address $address, array $data): Document
    {
        $validator = $this->validation->make($data, [
            'client_name' => ['string', 'max:255'],
            'client_uri' => ['filled', 'string', 'url:https'],
            'logo_uri' => ['filled', 'string', 'url:https'],
            'tos_uri' => ['string'],
            'policy_uri' => ['string'],
            'jwks_uri' => ['string'],
            'scope' => ['string'],
            'application_type' => ['string'],
            'software_id' => ['string'],
            'software_version' => ['string'],
            'token_endpoint_auth_method' => ['filled', 'string', 'in:none'],
            'redirect_uris' => ['required', 'list', 'max:10'],
            'redirect_uris.*' => ['required', 'string', 'max:2048'],
            'grant_types' => ['filled', 'list', 'contains:authorization_code'],
            'grant_types.*' => ['string'],
            'response_types' => ['filled', 'list', 'contains:code'],
            'response_types.*' => ['string'],
            'contacts' => ['list'],
            'contacts.*' => ['string'],
            'client_secret' => ['missing'],
            'client_secret_expires_at' => ['missing'],
        ]);

        if ($validator->fails()) {
            throw new UnusableDocumentException($validator->errors()->first());
        }

        if (($data['client_id'] ?? null) !== $address->url) {
            throw new UnusableDocumentException("the document's client_id does not match its address");
        }

        foreach ($data['redirect_uris'] as $redirectUri) {
            try {
                $uri = UriString::parse($redirectUri);
            } catch (SyntaxError) {
                throw new UnusableDocumentException('a redirect address is malformed');
            }

            if (($uri['host'] ?? '') === '' || $uri['user'] !== null) {
                throw new UnusableDocumentException('a redirect address is relative, has no host or has user information');
            }

            if ($uri['fragment'] !== null) {
                throw new UnusableDocumentException('a redirect address has a fragment');
            }

            $loopback = Loopback::isRedirect($redirectUri);
            $scheme = strtolower((string) $uri['scheme']);

            if ($scheme !== 'https' && ! ($scheme === 'http' && $loopback)) {
                throw new UnusableDocumentException('a redirect address is neither https nor plain http on a loopback host');
            }

            if ($loopback && ! Passport::$clientMetadataDocuments['allowLoopbackRedirects']) {
                throw new UnusableDocumentException('a redirect address is a loopback address, which is not allowed');
            }
        }

        $name = $data['client_name'] ?? '';

        return new Document(
            $address->url,
            trim($name) === '' ? $address->host : $name,
            $data['redirect_uris'],
            $data['client_uri'] ?? null,
            $data['logo_uri'] ?? null,
        );
    }

    /**
     * Let the application refuse a document that Passport has validated.
     *
     * @param  array<string, mixed>  $data
     *
     * @throws \Laravel\Passport\ClientMetadata\UnusableDocumentException
     */
    protected function applyValidationHook(array $data, string $url): void
    {
        if (! Passport::$clientMetadataDocumentValidator instanceof Closure) {
            return;
        }

        $reason = (Passport::$clientMetadataDocumentValidator)($data, $url);

        if (is_string($reason) && $reason !== '') {
            throw new UnusableDocumentException("the application refused the document: {$reason}");
        }
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

        return Cache::lock($this->key($url).':lock', Passport::$clientMetadataDocuments['connectTimeout'] +
            Passport::$clientMetadataDocuments['timeout'] + 5);
    }

    /**
     * Get the cache key of the validated document of the given address.
     *
     * The key carries the settings that decide whether a document is valid, so that a document
     * that was validated under other settings is never used, and a format version that changes
     * whenever the "Document" class changes, so that an entry of another shape is never read.
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
        Log::warning('Client metadata document refused: '.rtrim($reason, '.').'.', [
            'host' => parse_url($url, PHP_URL_HOST) ?: null,
        ]);

        throw InvalidClientMetadataException::unusable($request);
    }
}
