<?php

namespace Laravel\Passport\ClientMetadata;

use Exception;
use GuzzleHttp\Exception\TransferException;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Http;
use Laravel\Passport\Passport;

/**
 * @internal
 */
class Fetcher
{
    /**
     * The maximum nesting of the JSON a document may contain.
     */
    protected const MAXIMUM_NESTING = 8;

    /**
     * Fetch and validate the document published at the given address.
     *
     * @throws \Laravel\Passport\ClientMetadata\UnusableDocumentException
     */
    public function fetch(Address $address): Fetched
    {
        $configuration = Passport::$clientMetadataConfiguration;

        $sink = new LimitedStream($configuration->maximumSize);

        try {
            $response = Http::accept('application/json')
                ->withoutRedirecting()
                ->connectTimeout($configuration->connectTimeout)
                ->timeout($configuration->timeout)
                ->withOptions([
                    'sink' => $sink,
                    'curl' => [CURLOPT_PROTOCOLS => CURLPROTO_HTTPS],
                ])
                ->get($address->url);
        } catch (ConnectionException|TransferException $e) {
            throw new UnusableDocumentException(
                $sink->exceeded ? 'the document is larger than the maximum size' : 'the document could not be fetched',
                previous: $e
            );
        }

        if ($response->status() !== 200) {
            throw new UnusableDocumentException("the document answered with status {$response->status()}");
        }

        $document = app(DocumentValidator::class)->validate(
            $address, $this->decode($response, $configuration->maximumSize)
        );

        return new Fetched($document, $this->lifetime($response, $configuration));
    }

    /**
     * Get the number of seconds the document in the given response stays fresh.
     */
    protected function lifetime(Response $response, Configuration $configuration): int
    {
        $directives = array_map(trim(...), explode(',', strtolower($response->header('Cache-Control'))));

        $lifetime = match (true) {
            in_array('no-store', $directives, true), in_array('no-cache', $directives, true) => 0,
            default => $this->maxAge($directives) ?? $this->expiresIn($response) ?? $configuration->defaultLifetime,
        };

        return max($configuration->minimumLifetime, min($lifetime, $configuration->maximumLifetime));
    }

    /**
     * Get the "max-age" of the given Cache-Control directives.
     *
     * @param  string[]  $directives
     */
    protected function maxAge(array $directives): ?int
    {
        foreach ($directives as $directive) {
            if (preg_match('/^max-age\s*=\s*"?(\d+)"?$/', $directive, $matches) === 1) {
                return (int) $matches[1];
            }
        }

        return null;
    }

    /**
     * Get the number of seconds until the "Expires" header of the given response.
     */
    protected function expiresIn(Response $response): ?int
    {
        if (! $response->hasHeader('Expires')) {
            return null;
        }

        try {
            return max(0, Date::parse($response->header('Expires'))->getTimestamp() - Date::now()->getTimestamp());
        } catch (Exception) {
            // An invalid date means the document has already expired.
            return 0;
        }
    }

    /**
     * Decode the JSON object in the given response.
     *
     * @return array<string, mixed>
     *
     * @throws \Laravel\Passport\ClientMetadata\UnusableDocumentException
     */
    protected function decode(Response $response, int $maximumSize): array
    {
        $mediaType = strtolower(trim(explode(';', $response->header('Content-Type'))[0]));

        if ($mediaType !== 'application/json' && preg_match('#^application/[a-z0-9!\#$&^_.+-]+\+json$#D', $mediaType) !== 1) {
            throw new UnusableDocumentException('the document is not served as JSON');
        }

        $body = $response->body();

        if (strlen($body) > $maximumSize) {
            throw new UnusableDocumentException('the document is larger than the maximum size');
        }

        // The decoder counts one level more than the containers a document nests.
        $data = json_decode($body, true, static::MAXIMUM_NESTING + 1);

        if (json_last_error() === JSON_ERROR_DEPTH) {
            throw new UnusableDocumentException('the document is nested too deeply');
        }

        if (! is_array($data) || ! str_starts_with(ltrim($body, " \t\r\n"), '{')) {
            throw new UnusableDocumentException('the document is not a JSON object');
        }

        return $data;
    }
}
