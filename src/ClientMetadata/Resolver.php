<?php

namespace Laravel\Passport\ClientMetadata;

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

        $existing = $this->clients->findByMetadataDocumentUrl($url);

        if ($existing?->revoked) {
            $this->refuse($request, $url, 'the client has been revoked');
        }

        try {
            $document = $this->fetcher->fetch($url);
        } catch (UnusableDocumentException $e) {
            $this->refuse($request, $url, $e->getMessage());
        }

        $client = $this->clients->syncFromMetadataDocument($document, $existing);

        if ($client->revoked) {
            $this->refuse($request, $url, 'the client has been revoked');
        }

        return new ResolvedClient($client, $document);
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
