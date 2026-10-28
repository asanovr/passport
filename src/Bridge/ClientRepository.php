<?php

namespace Laravel\Passport\Bridge;

use Illuminate\Contracts\Hashing\Hasher;
use Laravel\Passport\Client as ClientModel;
use Laravel\Passport\ClientMetadata\Resolver;
use Laravel\Passport\ClientRepository as ClientModelRepository;
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
        if (Resolver::isAddress($clientIdentifier)) {
            $record = $this->clients->findActiveByMetadataDocumentUrl($clientIdentifier);
        } else {
            $record = $this->clients->findActive($clientIdentifier);

            // The bare identifier of a client that is identified by a metadata document
            // is never accepted: the client is only reachable through its document.
            if ($record?->getAttribute('metadata_document_url') !== null) {
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
            ! empty($model->getAttribute('metadata_document_url'))
        );
    }
}
