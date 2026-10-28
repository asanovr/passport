<?php

namespace Laravel\Passport\ClientMetadata;

use Composer\InstalledVersions;
use Exception;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\TransferException;
use GuzzleHttp\RequestOptions;
use Illuminate\Http\Client\HttpClientException;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Http;
use Laravel\Passport\Passport;
use Psr\Http\Message\RequestInterface;

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
     * Create a new fetcher instance.
     */
    public function __construct(
        protected DocumentValidator $validator,
        protected Network $network,
    ) {
    }

    /**
     * Fetch and validate the document published at the given address.
     *
     * @throws \Laravel\Passport\ClientMetadata\UnusableDocumentException
     */
    public function fetch(Address $address): FetchedDocument
    {
        $configuration = Passport::$clientMetadataConfiguration;

        $sink = new LimitedStream($configuration->maximumSize);

        // Everything that decides how safe the fetch is, is set here and not left to the application's
        // global HTTP client options.
        $options = [
            'sink' => $sink,
            'verify' => true,
            'allow_redirects' => false,
            'stream' => false,
            'connect_timeout' => $configuration->connectTimeout,
            'timeout' => $configuration->timeout,
            'curl' => [],
        ];

        if (defined(RequestOptions::class.'::PROTOCOLS')) {
            $options['protocols'] = ['https'];
        } else {
            $options['curl'][CURLOPT_PROTOCOLS] = CURLPROTO_HTTPS;
        }

        if ($configuration->proxy !== null) {
            // The proxy resolves the host and decides which addresses it may reach.
            $options['proxy'] = $configuration->proxy;

            // The proxy is for every host, whatever the "NO_PROXY" environment variable says.
            if ($this->curlReadsProxyEnvironment()) {
                $options['curl'][CURLOPT_NOPROXY] = '';
            }
        } else {
            // An empty proxy keeps the proxy environment variables from redirecting the fetch.
            $options['proxy'] = '';

            if (! $configuration->allowPrivateNetworks) {
                $options['curl'] += $this->pin($address);
            }
        }

        try {
            $response = Http::accept('application/json')
                ->withOptions($options)
                ->withMiddleware($this->ownCurlOptions($options['curl']))
                ->get($address->url);
        } catch (HttpClientException|TransferException $e) {
            throw new UnusableDocumentException(match (true) {
                $sink->exceeded => 'the document is larger than the maximum size',
                str_contains($e->getMessage(), 'cURL error 28') => 'the request for the document timed out',
                default => 'the document could not be fetched',
            }, previous: $e);
        }

        if ($response->status() !== 200) {
            throw new UnusableDocumentException("the document answered with status {$response->status()}");
        }

        $data = $this->decode($response, $configuration->maximumSize);

        $document = $this->validator->validate($address, $data);

        return new FetchedDocument($document, $this->lifetime($response, $configuration), $data);
    }

    /**
     * Get the middleware that sets the cURL options of the request to the given ones, and nothing the HTTP client
     * has been given for every request.
     *
     * The options are merged recursively, so the "curl" option of the application's global options would
     * otherwise stay, and cURL applies it after the options that make the fetch safe. Global middleware still runs.
     *
     * @param  array<int, mixed>  $curl
     */
    protected function ownCurlOptions(array $curl): callable
    {
        return fn (callable $handler): callable => fn (RequestInterface $request, array $options) => $handler(
            $request, ['curl' => $curl] + $options
        );
    }

    /**
     * Determine if cURL itself reads the "NO_PROXY" environment variable for a proxy it has been given.
     *
     * Guzzle 7.12 resolves the proxy environment itself and deprecates the cURL option that turns this
     * off, and Guzzle 8 refuses it. Earlier releases leave it to cURL.
     */
    protected function curlReadsProxyEnvironment(): bool
    {
        if (ClientInterface::MAJOR_VERSION >= 8) {
            return false;
        }

        return version_compare(InstalledVersions::getVersion('guzzlehttp/guzzle') ?? '0', '7.12.0', '<');
    }

    /**
     * Get the cURL options that pin the connection to the vetted addresses of the host.
     *
     * @return array<int, mixed>
     *
     * @throws \Laravel\Passport\ClientMetadata\UnusableDocumentException
     */
    protected function pin(Address $address): array
    {
        if (! $this->network->canPin()) {
            throw new UnusableDocumentException('connections cannot be pinned to the vetted addresses');
        }

        $addresses = $this->network->publicAddresses($address->host);

        // A host that is an address needs no pin.
        if (filter_var(trim($address->host, '[]'), FILTER_VALIDATE_IP) !== false) {
            return [];
        }

        return [CURLOPT_RESOLVE => ["{$address->host}:{$address->port}:".implode(',', array_map(
            fn (string $ip): string => str_contains($ip, ':') ? "[{$ip}]" : $ip, $addresses
        ))]];
    }

    /**
     * Get the number of seconds the document in the given response stays fresh.
     *
     * The freshness is that of RFC 9111: the time the response has already spent in a cache, as the "Age"
     * header says, is not counted again, and a "max-age" that is not valid makes the response stale.
     */
    protected function lifetime(Response $response, Configuration $configuration): int
    {
        $directives = array_map(trim(...), explode(',', strtolower($response->header('Cache-Control'))));

        $lifetime = match (true) {
            in_array('no-store', $directives, true), in_array('no-cache', $directives, true) => 0,
            default => $this->maxAge($directives) ?? $this->expiresIn($response) ?? $configuration->defaultLifetime,
        };

        if ($lifetime > 0 && $this->hasExplicitFreshness($directives, $response)) {
            $lifetime = max(0, $lifetime - $this->age($response));
        }

        return max($configuration->minimumLifetime, min($lifetime, $configuration->maximumLifetime));
    }

    /**
     * Determine if the given response says itself how long it stays fresh.
     *
     * @param  string[]  $directives
     */
    protected function hasExplicitFreshness(array $directives, Response $response): bool
    {
        foreach ($directives as $directive) {
            if (str_starts_with($directive, 'max-age')) {
                return true;
            }
        }

        return $response->hasHeader('Expires') && $this->date($response) !== null;
    }

    /**
     * Get the number of seconds the given response has already spent in caches.
     */
    protected function age(Response $response): int
    {
        $age = trim($response->header('Age'));

        return preg_match('/^\d+$/D', $age) === 1 ? (int) $age : 0;
    }

    /**
     * Get the date the given response says it was generated at.
     */
    protected function date(Response $response): ?int
    {
        if (! $response->hasHeader('Date')) {
            return null;
        }

        try {
            return Date::parse($response->header('Date'))->getTimestamp();
        } catch (Exception) {
            return null;
        }
    }

    /**
     * Get the "max-age" of the given Cache-Control directives, which is 0 when its value is not valid.
     *
     * @param  string[]  $directives
     */
    protected function maxAge(array $directives): ?int
    {
        foreach ($directives as $directive) {
            if (! str_starts_with($directive, 'max-age')) {
                continue;
            }

            return preg_match('/^max-age\s*=\s*"?(\d+)"?$/D', $directive, $matches) === 1 ? (int) $matches[1] : 0;
        }

        return null;
    }

    /**
     * Get the number of seconds from the "Date" of the given response, or else from now, until its "Expires" header.
     */
    protected function expiresIn(Response $response): ?int
    {
        if (! $response->hasHeader('Expires')) {
            return null;
        }

        try {
            $expires = Date::parse($response->header('Expires'))->getTimestamp();
        } catch (Exception) {
            // An invalid date means the document has already expired.
            return 0;
        }

        return max(0, $expires - ($this->date($response) ?? Date::now()->getTimestamp()));
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
