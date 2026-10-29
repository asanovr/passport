<?php

namespace Laravel\Passport\ClientMetadata;

use Closure;
use Illuminate\Contracts\Validation\Factory as ValidationFactory;
use Laravel\Passport\Passport;
use League\Uri\Exceptions\SyntaxError;
use League\Uri\UriString;

/**
 * Validates the JSON of a Client ID Metadata Document.
 */
class DocumentValidator
{
    /**
     * Create a new document validator instance.
     */
    public function __construct(
        protected ValidationFactory $validation,
    ) {
    }

    /**
     * Validate the decoded document published at the given address, and let the application refuse it.
     *
     * @param  array<string, mixed>  $data
     *
     * @throws \Laravel\Passport\ClientMetadata\UnusableDocumentException
     */
    public function validate(Address $address, array $data): Document
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

        $document = new Document(
            $address->url,
            trim($name) === '' ? $address->host : $name,
            $data['redirect_uris'],
            $data['client_uri'] ?? null,
            $data['logo_uri'] ?? null,
        );

        $this->applyValidationHook($data, $address->url);

        return $document;
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
}
