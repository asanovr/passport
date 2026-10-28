<?php

namespace Laravel\Passport\Exceptions;

use League\OAuth2\Server\Exception\OAuthServerException as LeagueException;
use Psr\Http\Message\ServerRequestInterface;

class InvalidClientMetadataException extends LeagueException
{
    /**
     * Create a new exception for a client whose metadata document cannot be used.
     *
     * The message is deliberately generic: the reason is logged, never sent to the client.
     */
    public static function unusable(ServerRequestInterface $serverRequest): static
    {
        $exception = new static("The client's metadata document could not be used.", 4, 'invalid_client', 401);

        $exception->setServerRequest($serverRequest);

        return $exception;
    }
}
