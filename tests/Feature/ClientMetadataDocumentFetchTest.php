<?php

namespace Laravel\Passport\Tests\Feature;

use Composer\InstalledVersions;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Psr7\Response as PsrResponse;
use GuzzleHttp\Psr7\Uri;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Request;
use Illuminate\Http\Client\RequestException;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Laravel\Passport\Client;
use Laravel\Passport\ClientMetadata\LimitedStream;
use Laravel\Passport\Passport;
use PHPUnit\Framework\Attributes\DataProvider;
use Workbench\Database\Factories\UserFactory;

class ClientMetadataDocumentFetchTest extends PassportTestCase
{
    use InteractsWithClientMetadataDocuments;

    protected function setUp(): void
    {
        parent::setUp();

        Passport::tokensCan(['create' => 'Create', 'read' => 'Read']);
        Passport::authorizationView(fn ($params) => $params);
        Passport::clientMetadataDocuments();

        Http::preventStrayRequests();

        $this->actingAs(UserFactory::new()->create(), 'web');
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function malformedAddresses(): array
    {
        return [
            'longer than 255 bytes' => ['https://client.example/'.str_repeat('a', 240)],
            'control character' => ["https://client.example/a\x01b"],
            'non-ASCII character' => ['https://client.example/ü'],
            'backslash' => ['https://client.example/a\\b'],
            'no host' => ['https:///oauth/client.json'],
            'a port' => ['https://client.example:8443/oauth/client.json'],
            'the default port' => ['https://client.example:443/oauth/client.json'],
            'no path' => ['https://client.example'],
            'the root path' => ['https://client.example/'],
            'user information' => ['https://user@client.example/oauth/client.json'],
            'a query' => ['https://client.example/oauth/client.json?a=b'],
            'an empty query' => ['https://client.example/oauth/client.json?'],
            'a fragment' => ['https://client.example/oauth/client.json#top'],
            'a dot segment' => ['https://client.example/oauth/./client.json'],
            'a dot-dot segment' => ['https://client.example/oauth/../client.json'],
            'an encoded dot segment' => ['https://client.example/oauth/%2e/client.json'],
            'an underscore in the host' => ['https://cli_ent.example/oauth/client.json'],
            'a percent-encoded host' => ['https://client%2eexample/oauth/client.json'],
            'a sub-delimiter in the host' => ['https://client$.example/oauth/client.json'],
            'a trailing dot' => ['https://client.example./oauth/client.json'],
            'a number that is not an IPv4 address' => ['https://127.1/oauth/client.json'],
            'an IPv4 address that is out of range' => ['https://999.1.1.1/oauth/client.json'],
            'a hexadecimal IPv4 address' => ['https://0x7f.0.0.1/oauth/client.json'],
            'a decimal IPv4 address' => ['https://2130706433/oauth/client.json'],
            'brackets around a name' => ['https://[client.example]/oauth/client.json'],
            'an IPv6 address with a zone' => ['https://[fe80::1%25eth0]/oauth/client.json'],
            'an IPvFuture host' => ['https://[v1.x]/oauth/client.json'],
            'an IPv4 address in brackets' => ['https://[93.184.216.34]/oauth/client.json'],
        ];
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function ipAddresses(): array
    {
        return [
            'an IPv4 address' => ['https://93.184.216.34/oauth/client.json'],
            'an IPv6 address' => ['https://[2606:2800:220:1:248:1893:25c8:1946]/oauth/client.json'],
            'an IPv6 address that is not written in its canonical form' => ['https://[2606:4700:0:0:0:0:0:1]/oauth/client.json'],
        ];
    }

    #[DataProvider('ipAddresses')]
    public function testAnIpAddressIsAnAcceptableHost(string $address)
    {
        $this->publish(url: $address);

        // The HTTP client may send the address in another notation, such as the canonical form of an IPv6 address.
        $this->published[(string) new Uri($address)] = $this->published[$address];

        $this->authorize($address)->assertOk();
        $this->assertSame(1, $this->requestsSent());
    }

    #[DataProvider('malformedAddresses')]
    public function testAMalformedAddressIsRefusedWithoutAFetch(string $address)
    {
        $this->publish();

        $this->assertRefused($this->authorize($address));
        $this->assertSame(0, $this->requestsSent());
    }

    public function testAnHttpAddressIsNotAMetadataDocumentAddress()
    {
        $this->publish();

        $response = $this->authorize('http://client.example/oauth/client.json');

        $response->assertStatus(401);
        $this->assertSame('invalid_client', $response->json('error'));
        $this->assertSame(0, $this->requestsSent());
    }

    public function testAnAddressWithAnEmptyPortIsFetchedOnceAndRefusedForNotMatchingTheDocument()
    {
        Log::spy();
        $this->publish();

        $this->assertRefused($this->authorize('https://client.example:/oauth/client.json'));

        $this->assertSame(['https://client.example/oauth/client.json'], array_map(fn (Request $request): string => $request->url(), $this->sentRequests()));
        $this->assertRefusalLogged('client_id does not match its address');
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function documentsThatAreNotObjects(): array
    {
        return [
            'an empty array' => ['[]'],
            'an empty object' => ['{}'],
            'an object with a numeric key' => ['{"0":"https://client.example/oauth/client.json"}'],
            'a string' => ['"https://client.example/oauth/client.json"'],
        ];
    }

    #[DataProvider('documentsThatAreNotObjects')]
    public function testADocumentThatIsNotAJsonObjectIsRefused(string $body)
    {
        Log::spy();
        $this->publish($body);

        $this->assertRefused($this->authorize());

        $this->assertRefusalLogged('The document is not a JSON object.');
    }

    public function testAHostInCapitalsIsFetchedAndPinnedByItsLowerCaseName()
    {
        $url = 'https://Client.Example/oauth/client.json';
        $this->publish($this->document(url: $url), url: 'https://client.example/oauth/client.json');

        $this->authorize($url)->assertOk();

        $this->assertSame($url, Client::query()->sole()->metadata_document_url);
        $this->assertSame(['client.example:443:93.184.216.34'], $this->requestOptions[0]['curl'][CURLOPT_RESOLVE]);
    }

    public function testAnAddressWithAPortIsAcceptedWhilePrivateNetworksAreAllowed()
    {
        Passport::clientMetadataDocuments(allowPrivateNetworks: true);
        $url = 'https://client.example:8443/oauth/client.json';
        $this->publish(url: $url);

        $this->authorize($url)->assertOk();
        $this->assertSame($url, Client::query()->sole()->metadata_document_url);
        $this->assertSame($url, $this->sentRequests()[0]->url());
    }

    public function testTheRequestIsAnHttpsGetThatAcceptsJsonAndNeverFollowsRedirects()
    {
        $this->publish();

        $this->authorize()->assertOk();

        $request = $this->sentRequests()[0];
        $options = $this->requestOptions[0];

        $this->assertSame('GET', $request->method());
        $this->assertSame($this->documentUrl, $request->url());
        $this->assertSame(['application/json'], $request->header('Accept'));
        $this->assertFalse($options['allow_redirects']);
        $this->assertHttpsOnly($options);
        $this->assertSame(2, $options['connect_timeout']);
        $this->assertSame(3, $options['timeout']);
    }

    public function testTheTimeoutsAreSettings()
    {
        Passport::clientMetadataDocuments(connectTimeout: 1, timeout: 5);
        $this->publish();

        $this->authorize()->assertOk();

        $this->assertSame(1, $this->requestOptions[0]['connect_timeout']);
        $this->assertSame(5, $this->requestOptions[0]['timeout']);
    }

    public function testARedirectIsNotFollowed()
    {
        $this->publish('', 302, ['Location' => 'https://client.example/elsewhere.json']);
        $this->publish($this->document(url: 'https://client.example/elsewhere.json'), url: 'https://client.example/elsewhere.json');

        $this->assertRefused($this->authorize());
        $this->assertSame(1, $this->requestsSent());
    }

    #[DataProvider('refusedStatuses')]
    public function testAnyStatusOtherThan200IsRefused(int $status)
    {
        $this->publish($this->document(), $status);

        $this->assertRefused($this->authorize());
    }

    /**
     * @return array<string, array{0: int}>
     */
    public static function refusedStatuses(): array
    {
        return ['201' => [201], '404' => [404]];
    }

    public function testABodyLongerThanTheMaximumSizeIsRefused()
    {
        $this->publish($this->document(['padding' => str_repeat('a', 5200)]));

        $this->assertRefused($this->authorize());
    }

    public function testABodyOfExactlyTheMaximumSizeIsAccepted()
    {
        $body = json_encode($this->document(['padding' => '']));
        $body = json_encode($this->document(['padding' => str_repeat('a', 5120 - strlen($body))]));
        $this->assertSame(5120, strlen($body));
        $this->publish($body);

        $this->authorize()->assertOk();
    }

    public function testTheMaximumSizeIsASetting()
    {
        Passport::clientMetadataDocuments(maximumSize: 100);
        $this->publish();

        $this->assertRefused($this->authorize());
    }

    public function testTheTransferStopsAtTheMaximumSize()
    {
        $this->publish();
        $this->authorize()->assertOk();

        $sink = $this->requestOptions[0]['sink'];

        $this->assertInstanceOf(LimitedStream::class, $sink);
        $this->assertSame(0, $sink->write(str_repeat('a', 5121)));
        $this->assertTrue($sink->exceeded);
    }

    #[DataProvider('acceptedMediaTypes')]
    public function testTheMediaTypeMustBeJson(string $contentType, bool $accepted)
    {
        $this->publish(headers: ['Content-Type' => $contentType]);

        $response = $this->authorize();

        $accepted ? $response->assertOk() : $this->assertRefused($response);
    }

    /**
     * @return array<string, array{0: string, 1: bool}>
     */
    public static function acceptedMediaTypes(): array
    {
        return [
            'json' => ['application/json', true],
            'json with a charset' => ['application/json; charset=utf-8', true],
            'uppercase json' => ['Application/JSON', true],
            'a structured suffix' => ['application/ld+json', true],
            'html' => ['text/html', false],
            'a lookalike' => ['application/jsonp', false],
            'no media type' => ['', false],
        ];
    }

    /**
     * Get a value that nests the given number of containers.
     */
    protected static function nest(int $containers): mixed
    {
        return $containers === 0 ? 1 : ['a' => static::nest($containers - 1)];
    }

    #[DataProvider('invalidBodies')]
    public function testTheBodyMustBeAJsonObjectThatIsNotNestedTooDeeply(string $body)
    {
        $this->publish($body);

        $this->assertRefused($this->authorize());
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function invalidBodies(): array
    {
        return [
            'not JSON' => ['<html>hello</html>'],
            'empty' => [''],
            'a number' => ['1'],
        ];
    }

    public function testADocumentNestedNineLevelsDeepIsRefused()
    {
        Log::spy();
        $this->publish($this->document(['extra' => static::nest(8)]));

        $this->assertRefused($this->authorize());
        $this->assertRefusalLogged('The document is nested too deeply.');
    }

    public function testADocumentNestedEightLevelsDeepIsAccepted()
    {
        $this->publish($this->document(['extra' => static::nest(7)]));

        $this->authorize()->assertOk();
    }

    public function testAFailedConnectionIsRefused()
    {
        Http::fake(fn () => throw new ConnectionException('cURL error 28: Operation timed out'));

        $this->assertRefused($this->authorize());
    }

    public function testEveryRefusalIsLoggedWithTheHostAndNeverTheBody()
    {
        Log::spy();
        $this->publish('SECRET-BODY', 500);

        $this->assertRefused($this->authorize());
        $this->assertRefused($this->authorize('https://client.example/oauth/../client.json'));

        Log::shouldHaveReceived('warning')->twice();
        $this->assertRefusalLogged('status 500');
        $this->assertRefusalLogged('dot segment');
        Log::shouldNotHaveReceived('warning', fn (string $message): bool => str_contains($message, 'SECRET-BODY'));
    }

    /**
     * @return array<string, array{0: bool, 1: string}>
     */
    public static function failedErrorAnswers(): array
    {
        return [
            'an error answer that passes the size limit' => [true, 'larger than the maximum size'],
            'a timeout in the middle of an error answer' => [false, 'could not be fetched'],
        ];
    }

    #[DataProvider('failedErrorAnswers')]
    public function testAnErrorAnswerThatFailsTheTransferIsARefusalAndDelaysTheNextFetch(bool $overflows, string $reason)
    {
        Log::spy();
        $this->resolveHostsAsPublic();

        $attempts = 0;

        // The way the real transport reports an error answer whose body does not go through the sink.
        Http::fake(function (Request $request, array $options) use ($overflows, &$attempts) {
            $attempts++;
            $overflows && $options['sink']->write(str_repeat('x', 20000));

            throw new RequestException(new Response(new PsrResponse(503, [], 'SECRET-BODY')));
        });

        $this->assertRefused($this->authorize());
        $this->assertRefused($this->authorize());

        $this->assertSame(1, $attempts);
        $this->assertRefusalLogged($reason);
        $this->assertRefusalLogged('the next one is delayed');
        Log::shouldNotHaveReceived('warning', fn (string $message): bool => str_contains($message, 'SECRET-BODY'));
    }

    public function testWithAProxyNoHostBypassesItWhateverTheGuzzleVersion()
    {
        Passport::clientMetadataDocuments(proxy: 'http://proxy.example:3128');
        $this->publish();

        $this->authorize()->assertOk();

        $options = $this->requestOptions[0];

        $this->assertSame('http://proxy.example:3128', $options['proxy']);

        // Before Guzzle 7.12, cURL reads "NO_PROXY" by itself for a proxy it was given. Later releases
        // do that in Guzzle, which deprecates the option that stops it, and Guzzle 8 refuses it.
        $curlReadsTheEnvironment = ClientInterface::MAJOR_VERSION < 8
            && version_compare(InstalledVersions::getVersion('guzzlehttp/guzzle'), '7.12.0', '<');

        $curlReadsTheEnvironment
            ? $this->assertSame('', $options['curl'][CURLOPT_NOPROXY])
            : $this->assertArrayNotHasKey(CURLOPT_NOPROXY, $options['curl']);
    }

    public function testNoProxyOptionIsPassedWithoutAProxy()
    {
        $this->publish();

        $this->authorize()->assertOk();

        $this->assertArrayNotHasKey(CURLOPT_NOPROXY, $this->requestOptions[0]['curl']);
    }

    public function testHttpsIsEnforcedWithTheOptionTheInstalledGuzzleSupports()
    {
        $this->publish();

        $this->authorize()->assertOk();

        $this->assertHttpsOnly($this->requestOptions[0]);
    }

    public function testTheInstalledGuzzleRaisesNoDeprecationForTheFetch()
    {
        $deprecations = [];

        set_error_handler(function (int $level, string $message) use (&$deprecations): bool {
            $deprecations[] = $message;

            return true;
        }, E_DEPRECATED | E_USER_DEPRECATED);

        try {
            // Nothing listens on the port, so the transfer is set up for real and then refused.
            Http::preventStrayRequests(false);
            Passport::clientMetadataDocuments(allowPrivateNetworks: true);

            $this->assertRefused($this->authorize('https://127.0.0.1:1/oauth/client.json'));
        } finally {
            restore_error_handler();
        }

        $this->assertSame([], $deprecations);
    }

    public function testTheFetchNeverUsesTheStreamHandlerWhichCannotPin()
    {
        $this->publish();

        $this->authorize()->assertOk();

        $this->assertFalse($this->requestOptions[0]['stream']);
    }

    public function testTheApplicationsGlobalOptionsCannotLoosenTheFetch()
    {
        Http::globalOptions([
            'verify' => false,
            'allow_redirects' => true,
            'proxy' => 'http://elsewhere.example:3128',
            'stream' => true,
            'connect_timeout' => 60,
            'timeout' => 60,
        ]);
        $this->publish();

        $this->authorize()->assertOk();

        $options = $this->requestOptions[0];

        $this->assertTrue($options['verify']);
        $this->assertFalse($options['allow_redirects']);
        $this->assertSame('', $options['proxy']);
        $this->assertFalse($options['stream']);
        $this->assertSame(2, $options['connect_timeout']);
        $this->assertSame(3, $options['timeout']);
        $this->assertArrayHasKey(CURLOPT_RESOLVE, $options['curl']);
    }

    public function testTheApplicationsGlobalCurlOptionsNeverReachTheTransportButItsMiddlewareRuns()
    {
        Http::globalOptions(['curl' => [CURLOPT_SSL_VERIFYPEER => false, CURLOPT_FOLLOWLOCATION => true]]);

        $ran = 0;

        Http::globalMiddleware(function (callable $handler) use (&$ran) {
            return function ($request, array $options) use ($handler, &$ran) {
                $ran++;

                return $handler($request, $options);
            };
        });
        $this->publish();

        $this->authorize()->assertOk();

        $this->assertSame(1, $ran);
        $this->assertHttpsOnly($this->requestOptions[0]);
        $this->assertSame([], array_diff(array_keys($this->requestOptions[0]['curl']), [CURLOPT_RESOLVE, CURLOPT_PROTOCOLS]));
    }
}
