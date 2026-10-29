<?php

namespace Laravel\Passport\Bridge;

use Laravel\Passport\Passport;
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
     *
     * League matches "http://127.0.0.1" and "http://[::1]" this way for every client, and a client that is
     * identified by a metadata document comes back on whichever port is free.
     */
    protected function isLocalhostMatch(string $redirectUri, ClientEntityInterface $client): bool
    {
        if (! $client instanceof Client || ! $client->identifiedByMetadataDocument ||
            ! Passport::clientMetadataDocumentsEnabled() || ! Passport::$clientMetadataDocuments['allowLoopbackRedirects']) {
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

        foreach ((array) $client->getRedirectUri() as $listed) {
            try {
                if ((string) Uri::new($listed)->withPort(null) === (string) $requested->withPort(null)) {
                    return true;
                }
            } catch (SyntaxError) {
                continue;
            }
        }

        return false;
    }
}
