<?php

namespace Laravel\Passport\ClientMetadata;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;

/**
 * @internal
 */
class Fetcher
{
    /**
     * Fetch and validate the document published at the given address.
     *
     * @throws \Laravel\Passport\ClientMetadata\UnusableDocumentException
     */
    public function fetch(string $url): Document
    {
        try {
            $response = Http::acceptJson()->get($url);
        } catch (ConnectionException $e) {
            throw new UnusableDocumentException('the document could not be fetched', previous: $e);
        }

        if ($response->status() !== 200) {
            throw new UnusableDocumentException("the document answered with status {$response->status()}");
        }

        return app(DocumentValidator::class)->validate($url, json_decode($response->body(), true));
    }
}
