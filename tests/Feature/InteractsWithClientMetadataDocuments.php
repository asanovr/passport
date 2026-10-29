<?php

namespace Laravel\Passport\Tests\Feature;

use GuzzleHttp\RequestOptions;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Laravel\Passport\Passport;
use Throwable;
use Workbench\App\Models\User;
use Workbench\Database\Factories\UserFactory;

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
     * The exception the servers that publish documents fail with, instead of answering.
     */
    protected ?Throwable $failure = null;

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

        $this->resolveHostsAsPublic();

        Http::fake(function (Request $request, array $options) {
            $this->requestOptions[] = $options;

            if ($this->failure) {
                throw $this->failure;
            }

            return isset($this->published[$request->url()])
                ? Http::response(...$this->published[$request->url()])
                : Http::response('Not Found', 404);
        });
    }

    /**
     * Make every host that publishes a document a public one, unless a test already decided otherwise.
     */
    protected function resolveHostsAsPublic(): void
    {
        Passport::$clientMetadataHostResolver ??= fn (string $host): array => ['93.184.216.34'];
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
     * Assert that the options of a request that left the server allow https and nothing else.
     *
     * Guzzle has an option for it since 7.11, and a cURL option does it before that.
     *
     * @param  array<string, mixed>  $options
     */
    protected function assertHttpsOnly(array $options): void
    {
        if (defined(RequestOptions::class.'::PROTOCOLS')) {
            $this->assertSame(['https'], $options['protocols']);
            $this->assertArrayNotHasKey(CURLOPT_PROTOCOLS, $options['curl']);
        } else {
            $this->assertArrayNotHasKey('protocols', $options);
            $this->assertSame(CURLPROTO_HTTPS, $options['curl'][CURLOPT_PROTOCOLS]);
        }
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

    protected function signIn(): User
    {
        $this->actingAs($user = UserFactory::new()->create(), 'web');

        return $user;
    }

    /**
     * Approve the authorization request of the given address and exchange the code for tokens.
     *
     * @return array<string, mixed>
     */
    protected function connect(?string $clientId = null, string $redirectUri = 'https://client.example/callback'): array
    {
        $response = $this->get('/oauth/authorize?'.$this->authorizationQuery($clientId, ['redirect_uri' => $redirectUri]))->assertOk();

        $response = $this->post('/oauth/authorize', ['auth_token' => $response->json('authToken')]);
        $response->assertRedirect();

        parse_str(parse_url($response->headers->get('Location'), PHP_URL_QUERY), $params);

        return $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $clientId ?? $this->documentUrl,
            'redirect_uri' => $redirectUri,
            'code' => $params['code'],
            'code_verifier' => $this->codeVerifier,
        ])->assertOk()->json();
    }

    /**
     * Assert that a refusal for the given reason was logged with the host of the document.
     */
    protected function assertRefusalLogged(string $reason, string $host = 'client.example', int $times = 1): void
    {
        Log::shouldHaveReceived('warning')->withArgs(
            fn (string $message, array $context): bool => $message === 'Client metadata document refused.'
                && array_keys($context) === ['reason', 'host']
                && $context['host'] === $host
                && str_contains($context['reason'], $reason)
        )->times($times);
    }
}
