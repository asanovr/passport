<?php

namespace Laravel\Passport\ClientMetadata;

use Closure;
use Composer\InstalledVersions;
use DateTimeImmutable;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\TransferException;
use GuzzleHttp\RequestOptions;
use Illuminate\Http\Client\HttpClientException;
use Illuminate\Http\Client\Response;
use Illuminate\Http\Response as HttpResponse;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Laravel\Passport\Passport;
use Psr\Http\Message\RequestInterface;
use Symfony\Component\HttpFoundation\HeaderBag;
use Symfony\Component\HttpFoundation\IpUtils;

/**
 * Fetches the document published at an address, only from hosts that are reachable from the whole internet.
 */
class Fetcher
{
    /**
     * The IPv4 ranges that are not globally reachable, as CIDR blocks.
     *
     * @var string[]
     */
    protected const NON_GLOBAL_IPV4 = [
        '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12',
        '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15',
        '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
    ];

    /**
     * The IPv6 ranges inside the global unicast block that are not globally reachable, as CIDR blocks.
     *
     * @var string[]
     */
    protected const NON_GLOBAL_IPV6 = [
        '2001::/32', '2001:2::/48', '2001:10::/28', '2001:db8::/32', '2002::/16', '3fff::/20',
    ];

    /**
     * The maximum nesting of the JSON a document may contain.
     */
    protected const MAXIMUM_NESTING = 8;

    /**
     * Fetch the document published at the given address and decode it.
     *
     * @return array{0: array<string, mixed>, 1: int} The document as it was published and the seconds it stays fresh.
     *
     * @throws \Laravel\Passport\ClientMetadata\UnusableDocumentException
     */
    public function fetch(Address $address): array
    {
        $configuration = Passport::$clientMetadataDocuments;

        $sink = new LimitedStream($configuration['maximumSize']);

        // Everything that decides how safe the fetch is, is set here and not left to the application's
        // global HTTP client options.
        $options = [
            'sink' => $sink,
            'verify' => true,
            'allow_redirects' => false,
            'stream' => false,
            'connect_timeout' => $configuration['connectTimeout'],
            'timeout' => $configuration['timeout'],
            'curl' => [],
        ];

        if (defined(RequestOptions::class.'::PROTOCOLS')) {
            $options['protocols'] = ['https'];
        } else {
            $options['curl'][CURLOPT_PROTOCOLS] = CURLPROTO_HTTPS;
        }

        if ($configuration['proxy'] !== null) {
            // The proxy resolves the host and decides which addresses it may reach.
            $options['proxy'] = $configuration['proxy'];

            // The proxy is for every host, whatever the "NO_PROXY" environment variable says.
            if ($this->curlReadsProxyEnvironment()) {
                $options['curl'][CURLOPT_NOPROXY] = '';
            }
        } else {
            // An empty proxy keeps the proxy environment variables from redirecting the fetch.
            $options['proxy'] = '';

            if (! $configuration['allowPrivateNetworks']) {
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

        return [$this->decode($response, $configuration['maximumSize']), $this->lifetime($response, $configuration)];
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
        if (! $this->canPin()) {
            throw new UnusableDocumentException('connections cannot be pinned to the vetted addresses');
        }

        $addresses = $this->publicAddresses($address->host);

        // A host that is an address needs no pin.
        if (filter_var(trim($address->host, '[]'), FILTER_VALIDATE_IP) !== false) {
            return [];
        }

        return [CURLOPT_RESOLVE => ["{$address->host}:443:".implode(',', array_map(
            fn (string $ip): string => str_contains($ip, ':') ? "[{$ip}]" : $ip, $addresses
        ))]];
    }

    /**
     * Get the number of seconds the document in the given response stays fresh.
     *
     * The freshness is that of RFC 9111: the time the response has already spent in a cache, as the "Age"
     * header says, is not counted again, and "s-maxage" is read before "max-age" because the cache is shared.
     *
     * @param  array{defaultLifetime: int, minimumLifetime: int, maximumLifetime: int}  $configuration
     */
    protected function lifetime(Response $response, array $configuration): int
    {
        // A response object invents "Cache-Control: no-cache, private" when it has none, so the header is read as sent.
        $directives = new HeaderBag(['Cache-Control' => $response->header('Cache-Control')]);

        $headers = $response->headers();

        // A "Date" that is missing or that Symfony cannot read is replaced by the time of receipt (RFC 9110, 6.6.1).
        if (DateTimeImmutable::createFromFormat(DATE_RFC2822, $response->header('Date')) === false) {
            $headers['Date'] = Date::now()->toRfc7231String();
        }

        $lifetime = match (true) {
            $directives->hasCacheControlDirective('no-store'), $directives->hasCacheControlDirective('no-cache') => 0,
            ($maxAge = (new HttpResponse('', 200, $headers))->getMaxAge()) === null => $configuration['defaultLifetime'],
            default => $maxAge - max(0, (int) $response->header('Age')),
        };

        return max($configuration['minimumLifetime'], min($lifetime, $configuration['maximumLifetime']));
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

        if (! Str::is(['application/json', 'application/*+json'], $mediaType)) {
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

    /**
     * Get the addresses of the given host, every one of which is globally reachable.
     *
     * @return string[]
     *
     * @throws \Laravel\Passport\ClientMetadata\UnusableDocumentException
     */
    protected function publicAddresses(string $host): array
    {
        $host = trim($host, '[]');

        $addresses = filter_var($host, FILTER_VALIDATE_IP) !== false ? [$host] : $this->resolve($host);

        if ($addresses === []) {
            throw new UnusableDocumentException('the host does not resolve to any address');
        }

        foreach ($addresses as $address) {
            if (! $this->isGlobal($address)) {
                throw new UnusableDocumentException("the host resolves to a non-public address ({$address})");
            }
        }

        return $addresses;
    }

    /**
     * Determine if connections can be pinned to the vetted addresses.
     */
    protected function canPin(): bool
    {
        // Guzzle only uses cURL, and so only honours a pin, when one of these functions exists.
        return extension_loaded('curl') && defined('CURLOPT_RESOLVE') &&
            ($this->hasFunction('curl_exec') || $this->hasFunction('curl_multi_exec'));
    }

    /**
     * Determine if the given function can be called.
     */
    protected function hasFunction(string $name): bool
    {
        return function_exists($name);
    }

    /**
     * Determine if the given IP address is globally reachable.
     */
    protected function isGlobal(string $address): bool
    {
        $packed = @inet_pton($address);

        if ($packed === false) {
            return false;
        }

        // IPv4-mapped (::ffff:0:0/96) and IPv4-compatible (::/96) forms stand for their IPv4 address.
        if (strlen($packed) === 16 && (str_starts_with($packed, str_repeat("\0", 10)."\xff\xff") || str_starts_with($packed, str_repeat("\0", 12)))) {
            $address = (string) inet_ntop(substr($packed, 12));
        }

        if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            return ! IpUtils::checkIp($address, static::NON_GLOBAL_IPV4);
        }

        // Only 2000::/3 is global unicast; the rest is reserved, local or multicast.
        return IpUtils::checkIp($address, '2000::/3') && ! IpUtils::checkIp($address, static::NON_GLOBAL_IPV6);
    }

    /**
     * Resolve the A and AAAA answers of the given host.
     *
     * @return string[]
     */
    protected function resolve(string $host): array
    {
        if (Passport::$clientMetadataHostResolver instanceof Closure) {
            return array_values((Passport::$clientMetadataHostResolver)($host));
        }

        $addresses = @gethostbynamel($host) ?: [];

        foreach (@dns_get_record($host, DNS_AAAA) ?: [] as $record) {
            $addresses[] = $record['ipv6'];
        }

        return array_values(array_unique($addresses));
    }
}
