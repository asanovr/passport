<?php

namespace Laravel\Passport\Bridge;

use Illuminate\Contracts\Hashing\Hasher;
use Laravel\Passport\Client as ClientModel;
use Laravel\Passport\ClientMetadata\Resolver;
use Laravel\Passport\ClientRepository as ClientModelRepository;
use Laravel\Passport\Passport;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;

class ClientRepository implements ClientRepositoryInterface
{
    /**
     * Create a new repository instance.
     */
    public function __construct(
        protected ClientModelRepository $clients,
        protected Hasher $hasher,
    ) {
    }

    /**
     * {@inheritdoc}
     */
    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
    {
        $isAddress = Resolver::isAddress($clientIdentifier);

        $record = $isAddress ? $this->clients->findActiveByMetadataDocumentUrl($clientIdentifier) : null;

        // An identifier that merely looks like an address, in an application that does not
        // accept metadata documents, is looked up exactly as it always has been.
        if ($record === null && (! $isAddress || ! Passport::clientMetadataDocumentsEnabled())) {
            $record = $this->clients->findActive($clientIdentifier);

            // The bare identifier of a client that is identified by a metadata document
            // is never accepted: the client is only reachable through its document.
            if (($record?->getAttributes()['metadata_document_url'] ?? null) !== null) {
                return null;
            }
        }

        return $record ? $this->fromClientModel($record) : null;
    }

    /**
     * {@inheritdoc}
     */
    public function validateClient(string $clientIdentifier, ?string $clientSecret, ?string $grantType): bool
    {
        $record = $this->clients->findActive($clientIdentifier);

        return $record && ! empty($clientSecret) && $this->hasher->check($clientSecret, $record->secret);
    }

    /**
     * Get the personal access client for the given provider.
     */
    public function getPersonalAccessClientEntity(string $provider): ?ClientEntityInterface
    {
        return $this->fromClientModel(
            $this->clients->personalAccessClient($provider)
        );
    }

    /**
     * Create a new client entity from the given client model instance.
     */
    protected function fromClientModel(ClientModel $model): ClientEntityInterface
    {
        return new Client(
            $model->getKey(),
            $model->name,
            $model->redirect_uris,
            $model->confidential(),
            $model->provider,
            $model->grant_types,
            ! empty($model->getAttributes()['metadata_document_url'] ?? null)
        );
    }
}
