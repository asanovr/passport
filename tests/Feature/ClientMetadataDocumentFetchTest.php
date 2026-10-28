<?php

namespace Laravel\Passport\Tests\Feature;

use Illuminate\Http\Client\ConnectionException;
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

    protected function authorize(?string $url = null)
    {
        return $this->get('/oauth/authorize?'.$this->authorizationQuery($url));
    }

    protected function assertRefused($response): void
    {
        $response->assertStatus(401);
        $response->assertHeaderMissing('Location');
        $this->assertSame('invalid_client', $response->json('error'));
        $this->assertSame(0, Client::query()->count());
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function malformedAddresses(): array
    {
        return [
            'plain http' => ['http://client.example/oauth/client.json'],
            'longer than 255 bytes' => ['https://client.example/'.str_repeat('a', 240)],
            'control character' => ["https://client.example/a\x01b"],
            'space' => ['https://client.example/a b'],
            'non-ASCII character' => ['https://client.example/ü'],
            'backslash' => ['https://client.example/a\\b'],
            'no host' => ['https:///oauth/client.json'],
            'a port' => ['https://client.example:8443/oauth/client.json'],
            'the default port' => ['https://client.example:443/oauth/client.json'],
            'an empty port' => ['https://client.example:/oauth/client.json'],
            'an IPv6 host with a port' => ['https://[2001:db8::1]:8443/oauth/client.json'],
            'no path' => ['https://client.example'],
            'the root path' => ['https://client.example/'],
            'user information' => ['https://user@client.example/oauth/client.json'],
            'a password' => ['https://user:secret@client.example/oauth/client.json'],
            'a query' => ['https://client.example/oauth/client.json?a=b'],
            'an empty query' => ['https://client.example/oauth/client.json?'],
            'a fragment' => ['https://client.example/oauth/client.json#top'],
            'a dot segment' => ['https://client.example/oauth/./client.json'],
            'a dot-dot segment' => ['https://client.example/oauth/../client.json'],
            'an encoded dot segment' => ['https://client.example/oauth/%2e/client.json'],
            'an encoded dot-dot segment' => ['https://client.example/oauth/%2E%2e/client.json'],
            'a half encoded dot-dot segment' => ['https://client.example/oauth/.%2e/client.json'],
        ];
    }

    #[DataProvider('malformedAddresses')]
    public function testAMalformedAddressIsRefusedWithoutAFetch(string $address)
    {
        $this->publish();

        $this->assertRefused($this->authorize($address));
        $this->assertSame(0, $this->requestsSent());
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

    public function testAllowingPrivateNetworksLiftsNothingElseFromTheAddressRules()
    {
        Passport::clientMetadataDocuments(allowPrivateNetworks: true);
        $this->publish();

        $this->assertRefused($this->authorize('https://client.example:8443/a?b=c'));
        $this->assertRefused($this->authorize('https://client.example:8443/'));
        $this->assertRefused($this->authorize('https://user@client.example:8443/a'));
        $this->assertSame(0, $this->requestsSent());
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
        $this->assertSame(['https'], $options['protocols']);
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
        return ['201' => [201], '204' => [204], '301' => [301], '304' => [304], '404' => [404], '500' => [500]];
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
            'a structured suffix with parameters' => ['application/vnd.api+json; charset=utf-8', true],
            'html' => ['text/html', false],
            'plain text' => ['text/plain', false],
            'json as text' => ['text/json', false],
            'a lookalike' => ['application/jsonp', false],
            'a lookalike suffix' => ['application/x+jsonp', false],
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
        $document = fn (array $extra) => json_encode([
            'client_id' => 'https://client.example/oauth/client.json',
            'redirect_uris' => ['https://client.example/callback'],
        ] + $extra);

        return [
            'not JSON' => ['<html>hello</html>'],
            'empty' => [''],
            'a list' => ['[{"client_id":"https://client.example/oauth/client.json"}]'],
            'a string' => ['"https://client.example/oauth/client.json"'],
            'a number' => ['1'],
            'nested nine levels' => [$document(['extra' => static::nest(8)])],
        ];
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
        Log::shouldHaveReceived('warning')->withArgs(
            fn (string $message, array $context): bool => str_contains($message, 'status 500') && $context === ['host' => 'client.example']
        )->once();
        Log::shouldHaveReceived('warning')->withArgs(
            fn (string $message, array $context): bool => str_contains($message, 'dot segment') && $context === ['host' => 'client.example']
        )->once();
        Log::shouldNotHaveReceived('warning', fn (string $message): bool => str_contains($message, 'SECRET-BODY'));
    }
}
