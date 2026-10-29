<?php

namespace Laravel\Passport\Exceptions;

use League\OAuth2\Server\Exception\OAuthServerException as LeagueException;
use Psr\Http\Message\ServerRequestInterface;

class InvalidClientMetadataException extends LeagueException
{
    /**
     * Create a new InvalidClientMetadataException for an unusable metadata document.
     */
    public static function unusable(ServerRequestInterface $serverRequest): static
    {
        $exception = new static("The client's metadata document could not be used.", 4, 'invalid_client', 401);

        $exception->setServerRequest($serverRequest);

        return $exception;
    }
}
