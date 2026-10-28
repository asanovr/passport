<?php

namespace Laravel\Passport\Tests\Feature;

use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

trait InteractsWithClientMetadataDocuments
{
    /**
     * The value that leaves a field out of a document.
     */
    protected const MISSING = '@@missing@@';

    protected string $documentUrl = 'https://client.example/oauth/client.json';

    protected string $codeVerifier;

    /**
     * The answers of the servers that publish documents, by address.
     *
     * @var array<string, array{0: array<string, mixed>|string, 1: int, 2: array<string, string>}>
     */
    protected array $published = [];

    protected bool $fakesDocuments = false;

    /**
     * The options of the requests that left the server, in the order they were sent.
     *
     * @var array<int, array<string, mixed>>
     */
    protected array $requestOptions = [];

    /**
     * Get a document published at the given address, with the given fields replaced.
     *
     * @param  array<string, mixed>  $overrides
     * @return array<string, mixed>
     */
    protected function document(array $overrides = [], ?string $url = null): array
    {
        return array_filter(array_replace([
            'client_id' => $url ?? $this->documentUrl,
            'client_name' => 'Example Agent',
            'redirect_uris' => ['https://client.example/callback'],
        ], $overrides), fn (mixed $value): bool => $value !== static::MISSING);
    }

    /**
     * Fake the answer of the server that publishes the given document.
     *
     * @param  array<string, mixed>|string|null  $body
     * @param  array<string, string>  $headers
     */
    protected function publish(array|string|null $body = null, int $status = 200, array $headers = ['Content-Type' => 'application/json'], ?string $url = null): void
    {
        $body ??= $this->document(url: $url);

        $this->published[$url ?? $this->documentUrl] = [is_array($body) ? json_encode($body) : $body, $status, $headers];

        if ($this->fakesDocuments) {
            return;
        }

        $this->fakesDocuments = true;

        Http::fake(function (Request $request, array $options) {
            $this->requestOptions[] = $options;

            return isset($this->published[$request->url()])
                ? Http::response(...$this->published[$request->url()])
                : Http::response('Not Found', 404);
        });
    }

    /**
     * Get the query of an authorization request that uses the given client id.
     *
     * @param  array<string, mixed>  $overrides
     */
    protected function authorizationQuery(?string $clientId = null, array $overrides = []): string
    {
        $this->codeVerifier = Str::random(128);

        return http_build_query(array_replace([
            'client_id' => $clientId ?? $this->documentUrl,
            'redirect_uri' => 'https://client.example/callback',
            'response_type' => 'code',
            'scope' => 'create read',
            'state' => Str::random(40),
            'code_challenge' => strtr(rtrim(base64_encode(hash('sha256', $this->codeVerifier, true)), '='), '+/', '-_'),
            'code_challenge_method' => 'S256',
        ], $overrides));
    }

    /**
     * Get the number of requests that left the server.
     */
    protected function requestsSent(): int
    {
        return Http::recorded()->count();
    }

    /**
     * Get the requests that left the server.
     *
     * @return \Illuminate\Http\Client\Request[]
     */
    protected function sentRequests(): array
    {
        return Http::recorded()->map(fn (array $pair): Request => $pair[0])->all();
    }
}
