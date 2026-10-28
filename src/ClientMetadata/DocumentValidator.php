<?php

namespace Laravel\Passport\ClientMetadata;

use GuzzleHttp\Psr7\Exception\MalformedUriException;
use GuzzleHttp\Psr7\Uri;

/**
 * @internal
 */
class DocumentValidator
{
    /**
     * The fields that must be a string, when present.
     *
     * @var string[]
     */
    protected const STRING_FIELDS = [
        'client_name', 'client_uri', 'logo_uri', 'tos_uri', 'policy_uri', 'jwks_uri', 'scope',
        'application_type', 'software_id', 'software_version', 'token_endpoint_auth_method',
    ];

    /**
     * The fields that must be a list of strings, when present.
     *
     * @var string[]
     */
    protected const LIST_FIELDS = ['redirect_uris', 'grant_types', 'response_types', 'contacts'];

    /**
     * The hosts a program on the user's computer is reached at.
     *
     * @var string[]
     */
    protected const LOOPBACK_HOSTS = ['127.0.0.1', '[::1]', 'localhost'];

    /**
     * Validate the decoded document published at the given address.
     *
     * @throws \Laravel\Passport\ClientMetadata\UnusableDocumentException
     */
    public function validate(Address $address, mixed $data): Document
    {
        if (! is_array($data) || array_is_list($data) && $data !== []) {
            throw new UnusableDocumentException('the document is not a JSON object');
        }

        foreach (static::STRING_FIELDS as $field) {
            if (array_key_exists($field, $data) && ! is_string($data[$field])) {
                throw new UnusableDocumentException("the document's {$field} is not a string");
            }
        }

        foreach (static::LIST_FIELDS as $field) {
            if (array_key_exists($field, $data) && (! is_array($data[$field]) || ! array_is_list($data[$field]) ||
                array_filter($data[$field], fn (mixed $value): bool => ! is_string($value)) !== [])) {
                throw new UnusableDocumentException("the document's {$field} is not a list of strings");
            }
        }

        if (($data['client_id'] ?? null) !== $address->url) {
            throw new UnusableDocumentException("the document's client_id does not match its address");
        }

        if (array_key_exists('client_secret', $data) || array_key_exists('client_secret_expires_at', $data)) {
            throw new UnusableDocumentException('the document contains a client secret');
        }

        if (($data['token_endpoint_auth_method'] ?? 'none') !== 'none') {
            throw new UnusableDocumentException('the document asks for client authentication');
        }

        if (isset($data['grant_types']) && ! in_array('authorization_code', $data['grant_types'], true)) {
            throw new UnusableDocumentException('the document does not use the authorization_code grant');
        }

        if (isset($data['response_types']) && ! in_array('code', $data['response_types'], true)) {
            throw new UnusableDocumentException('the document does not use the code response type');
        }

        foreach (['client_uri', 'logo_uri'] as $field) {
            if (isset($data[$field]) && ! $this->isHttps($data[$field])) {
                throw new UnusableDocumentException("the document's {$field} is not an https address");
            }
        }

        $name = $data['client_name'] ?? '';

        if (mb_strlen($name) > 255) {
            throw new UnusableDocumentException('the document\'s client_name is longer than 255 characters');
        }

        return new Document(
            $address->url,
            trim($name) === '' ? $address->host : $name,
            $this->redirectUris($data['redirect_uris'] ?? []),
            $data['client_uri'] ?? null,
            $data['logo_uri'] ?? null,
        );
    }

    /**
     * Validate the redirect addresses of the document.
     *
     * @param  string[]  $redirectUris
     * @return string[]
     *
     * @throws \Laravel\Passport\ClientMetadata\UnusableDocumentException
     */
    protected function redirectUris(array $redirectUris): array
    {
        if ($redirectUris === []) {
            throw new UnusableDocumentException('the document has no redirect_uris');
        }

        if (count($redirectUris) > 10) {
            throw new UnusableDocumentException('the document has more than 10 redirect_uris');
        }

        foreach ($redirectUris as $redirectUri) {
            if (mb_strlen($redirectUri) > 2048) {
                throw new UnusableDocumentException('a redirect address is longer than 2,048 characters');
            }

            if (str_contains($redirectUri, '#')) {
                throw new UnusableDocumentException('a redirect address has a fragment');
            }

            try {
                $uri = new Uri($redirectUri);
            } catch (MalformedUriException) {
                throw new UnusableDocumentException('a redirect address is malformed');
            }

            if ($uri->getHost() === '' || str_contains(explode('/', substr($redirectUri, strlen($uri->getScheme()) + 3))[0], '@')) {
                throw new UnusableDocumentException('a redirect address is relative, has no host or has user information');
            }

            if ($uri->getScheme() === 'https') {
                continue;
            }

            if ($uri->getScheme() !== 'http' || ! in_array($uri->getHost(), static::LOOPBACK_HOSTS, true)) {
                throw new UnusableDocumentException('a redirect address is neither https nor plain http on a loopback host');
            }
        }

        return $redirectUris;
    }

    /**
     * Determine if the given value is an https address with a host.
     */
    protected function isHttps(string $url): bool
    {
        try {
            $uri = new Uri($url);
        } catch (MalformedUriException) {
            return false;
        }

        return $uri->getScheme() === 'https' && $uri->getHost() !== '';
    }
}
