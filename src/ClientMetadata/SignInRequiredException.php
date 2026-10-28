<?php

namespace Laravel\Passport\ClientMetadata;

use RuntimeException;

/**
 * Thrown when a document would have to be fetched for someone who is not signed in.
 *
 * @internal
 */
class SignInRequiredException extends RuntimeException
{
    //
}
