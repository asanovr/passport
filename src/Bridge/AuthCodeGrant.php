<?php

namespace Laravel\Passport\Bridge;

use Illuminate\Support\Arr;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Grant\AuthCodeGrant as LeagueAuthCodeGrant;
use League\Uri\Exceptions\SyntaxError;
use League\Uri\Uri;
use Psr\Http\Message\ServerRequestInterface;

class AuthCodeGrant extends LeagueAuthCodeGrant
{
    /**
     * {@inheritdoc}
     */
    protected function validateRedirectUri(
        string $redirectUri,
        ClientEntityInterface $client,
        ServerRequestInterface $request
    ): void {
        if (! $this->isLocalhostMatch($redirectUri, $client)) {
            parent::validateRedirectUri($redirectUri, $client, $request);
        }
    }

    /**
     * Determine if the redirect address is a listed "http://localhost" address on any port.
     */
    protected function isLocalhostMatch(string $redirectUri, ClientEntityInterface $client): bool
    {
        if (! $client instanceof Client || ! $client->identifiedByMetadataDocument) {
            return false;
        }

        try {
            $requested = Uri::new($redirectUri);
        } catch (SyntaxError) {
            return false;
        }

        if ($requested->getScheme() !== 'http' || $requested->getHost() !== 'localhost') {
            return false;
        }

        foreach (Arr::wrap($client->getRedirectUri()) as $listed) {
            try {
                if ((string) Uri::new($listed)->withPort(null) === (string) $requested->withPort(null)) {
                    return true;
                }
            } catch (SyntaxError) {
                //
            }
        }

        return false;
    }
}
