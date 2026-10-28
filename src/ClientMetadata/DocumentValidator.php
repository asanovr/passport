<?php

namespace Laravel\Passport\ClientMetadata;

/**
 * @internal
 */
class DocumentValidator
{
    /**
     * Validate the decoded document published at the given address.
     *
     * @throws \Laravel\Passport\ClientMetadata\UnusableDocumentException
     */
    public function validate(string $url, mixed $data): Document
    {
        if (! is_array($data)) {
            throw new UnusableDocumentException('the document is not a JSON object');
        }

        if (($data['client_id'] ?? null) !== $url) {
            throw new UnusableDocumentException('the document\'s client_id does not match its address');
        }

        $redirectUris = $data['redirect_uris'] ?? null;

        if (! is_array($redirectUris) || $redirectUris === []) {
            throw new UnusableDocumentException('the document has no redirect_uris');
        }

        $name = $data['client_name'] ?? parse_url($url, PHP_URL_HOST);

        return new Document(
            $url,
            $name,
            array_values($redirectUris),
        );
    }
}
