<?php

namespace Laravel\Passport\Bridge;

use GuzzleHttp\Psr7\Exception\MalformedUriException;
use GuzzleHttp\Psr7\Uri;
use Laravel\Passport\Passport;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Grant\AuthCodeGrant as LeagueAuthCodeGrant;
use Psr\Http\Message\ServerRequestInterface;

/**
 * @internal
 */
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
        if (! $this->isLocalhostPortMatch($redirectUri, $client)) {
            parent::validateRedirectUri($redirectUri, $client, $request);
        }
    }

    /**
     * Determine if the redirect address only differs from a listed "localhost" address in its port.
     *
     * A client that is identified by a metadata document lists "http://localhost/callback" once and
     * comes back on whichever port is free. A listed address that names a port must match exactly.
     */
    protected function isLocalhostPortMatch(string $redirectUri, ClientEntityInterface $client): bool
    {
        if (! $client instanceof Client || ! $client->identifiedByMetadataDocument ||
            ! Passport::$clientMetadataConfiguration?->allowLoopbackRedirects) {
            return false;
        }

        try {
            $requested = new Uri($redirectUri);
        } catch (MalformedUriException) {
            return false;
        }

        if ($requested->getScheme() !== 'http' || $requested->getHost() !== 'localhost' || $requested->getUserInfo() !== '') {
            return false;
        }

        foreach ((array) $client->getRedirectUri() as $listed) {
            try {
                $listed = new Uri($listed);
            } catch (MalformedUriException) {
                continue;
            }

            if ($listed->getScheme() === 'http' && $listed->getHost() === 'localhost' && $listed->getPort() === null &&
                $listed->getUserInfo() === '' && $listed->getPath() === $requested->getPath() &&
                $listed->getQuery() === $requested->getQuery() && $requested->getFragment() === '') {
                return true;
            }
        }

        return false;
    }
}
