<?php

namespace Laravel\Passport\Tests\Feature;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Laravel\Passport\Client;
use Laravel\Passport\ClientMetadata\Network;
use Laravel\Passport\Passport;
use PHPUnit\Framework\Attributes\DataProvider;

class ClientMetadataDocumentNetworkTest extends PassportTestCase
{
    use InteractsWithClientMetadataDocuments;

    /**
     * The hosts the resolver was asked about.
     *
     * @var string[]
     */
    protected array $lookups = [];

    protected function setUp(): void
    {
        parent::setUp();

        Passport::tokensCan(['create' => 'Create', 'read' => 'Read']);
        Passport::authorizationView(fn ($params) => $params);
        Passport::clientMetadataDocuments();

        Http::preventStrayRequests();

        $this->signIn();
    }

    /**
     * Make the given host resolve to the given addresses.
     *
     * @param  string[]  $addresses
     */
    protected function resolveTo(array $addresses): void
    {
        Passport::resolveClientMetadataHostsUsing(function (string $host) use ($addresses): array {
            $this->lookups[] = $host;

            return $addresses;
        });
    }

    protected function authorize(?string $url = null)
    {
        return $this->get('/oauth/authorize?'.$this->authorizationQuery($url));
    }

    protected function assertRefused($response): void
    {
        $response->assertStatus(401);
        $this->assertSame('invalid_client', $response->json('error'));
        $this->assertSame("The client's metadata document could not be used.", $response->json('error_description'));
        $this->assertSame(0, Client::query()->count());
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function nonPublicAddresses(): array
    {
        return [
            '10/8' => ['10.0.0.1'],
            '172.16/12' => ['172.16.5.4'],
            '172.31.255.255' => ['172.31.255.255'],
            '192.168/16' => ['192.168.1.1'],
            '127/8' => ['127.0.0.1'],
            '127.255.255.254' => ['127.255.255.254'],
            '0/8' => ['0.0.0.0'],
            '0.1.2.3' => ['0.1.2.3'],
            '100.64/10' => ['100.64.0.1'],
            '100.127.255.255' => ['100.127.255.255'],
            '169.254/16' => ['169.254.0.1'],
            'the cloud metadata service' => ['169.254.169.254'],
            '198.18/15' => ['198.18.0.1'],
            '198.19.255.255' => ['198.19.255.255'],
            '240/4' => ['240.0.0.1'],
            'the broadcast address' => ['255.255.255.255'],
            '192.0.0/24' => ['192.0.0.8'],
            'TEST-NET-1' => ['192.0.2.1'],
            'TEST-NET-2' => ['198.51.100.7'],
            'TEST-NET-3' => ['203.0.113.9'],
            'multicast' => ['224.0.0.251'],
            'the unspecified IPv6 address' => ['::'],
            'the IPv6 loopback' => ['::1'],
            'IPv6 link-local' => ['fe80::1'],
            'IPv6 unique local' => ['fc00::1'],
            'IPv6 unique local (fd)' => ['fd12:3456::1'],
            'NAT64' => ['64:ff9b::808:808'],
            'local-use NAT64' => ['64:ff9b:1::1'],
            '6to4' => ['2002:808:808::1'],
            'Teredo' => ['2001::1'],
            'IPv6 documentation' => ['2001:db8::1'],
            'IPv6 multicast' => ['ff02::1'],
            'an IPv4-mapped private address' => ['::ffff:10.0.0.1'],
            'an IPv4-mapped loopback address' => ['::ffff:127.0.0.1'],
            'an IPv4-mapped metadata service address' => ['::ffff:a9fe:a9fe'],
            'an IPv4-compatible private address' => ['::10.0.0.1'],
            'an IPv4-compatible loopback address' => ['::127.0.0.1'],
            'garbage' => ['not-an-address'],
        ];
    }

    #[DataProvider('nonPublicAddresses')]
    public function testAHostThatResolvesToANonPublicAddressIsRefusedBeforeConnecting(string $address)
    {
        $this->publish();
        $this->resolveTo([$address]);

        $this->assertRefused($this->authorize());
        $this->assertSame(0, $this->requestsSent());
        $this->assertSame(['client.example'], $this->lookups);
    }

    /**
     * @return array<string, array{0: string[]}>
     */
    public static function publicAddresses(): array
    {
        return [
            'a public IPv4 address' => [['93.184.216.34']],
            'next to the shared range' => [['100.128.0.1']],
            'next to 172.16/12' => [['172.32.0.1']],
            'next to 198.18/15' => [['198.20.0.1']],
            'a public IPv6 address' => [['2606:4700::1111']],
            'both families' => [['93.184.216.34', '2606:4700::1111']],
            'an IPv4-mapped public address' => [['::ffff:93.184.216.34']],
        ];
    }

    /**
     * @param  string[]  $addresses
     */
    #[DataProvider('publicAddresses')]
    public function testAHostThatResolvesToPublicAddressesIsFetched(array $addresses)
    {
        $this->publish();
        $this->resolveTo($addresses);

        $this->authorize()->assertOk();
        $this->assertSame(1, $this->requestsSent());
    }

    public function testOneBadAnswerAmongGoodOnesRefusesTheHost()
    {
        $this->publish();

        $this->resolveTo(['93.184.216.34', '2606:4700::1111', '10.0.0.5']);
        $this->assertRefused($this->authorize());

        $this->resolveTo(['10.0.0.5', '93.184.216.34']);
        $this->assertRefused($this->authorize());

        $this->assertSame(0, $this->requestsSent());
    }

    public function testAHostWithoutAnAnswerIsRefused()
    {
        $this->publish();
        $this->resolveTo([]);

        $this->assertRefused($this->authorize());
        $this->assertSame(0, $this->requestsSent());
    }

    public function testTheSystemResolverIsUsedWhenTheHookIsNull()
    {
        $this->publish(url: 'https://localhost/oauth/client.json');
        Passport::resolveClientMetadataHostsUsing(null);

        $this->assertRefused($this->authorize('https://localhost/oauth/client.json'));
        $this->assertSame(0, $this->requestsSent());
    }

    public function testTheHookIsResetAfterEachTest()
    {
        $this->assertNull(Passport::$clientMetadataHostResolver);
    }

    public function testAnAddressThatIsAnIpAddressIsCheckedWithoutAResolver()
    {
        $this->resolveTo(['93.184.216.34']);

        $this->publish(url: 'https://192.168.1.10/oauth/client.json');
        $this->assertRefused($this->authorize('https://192.168.1.10/oauth/client.json'));

        $this->publish(url: 'https://[::1]/oauth/client.json');
        $this->assertRefused($this->authorize('https://[::1]/oauth/client.json'));

        $this->publish(url: 'https://8.8.8.8/oauth/client.json');
        $this->authorize('https://8.8.8.8/oauth/client.json')->assertOk();

        $this->assertSame([], $this->lookups);
        $this->assertSame(1, $this->requestsSent());
    }

    public function testTheConnectionIsPinnedToTheVettedAddresses()
    {
        $this->publish();
        $this->resolveTo(['93.184.216.34', '2606:4700::1111']);

        $this->authorize()->assertOk();

        $this->assertSame(
            ['client.example:443:93.184.216.34,[2606:4700::1111]'],
            $this->requestOptions[0]['curl'][CURLOPT_RESOLVE]
        );
        $this->assertHttpsOnly($this->requestOptions[0]);
    }

    public function testNothingIsFetchedWhenPinningIsNotAvailable()
    {
        $this->publish();
        $this->resolveTo(['93.184.216.34']);

        $this->app->bind(Network::class, UnpinnableNetwork::class);

        $this->assertRefused($this->authorize());
        $this->assertSame(0, $this->requestsSent());
    }

    public function testProxyEnvironmentVariablesAreIgnoredUnlessAProxyIsConfigured()
    {
        $this->publish();
        $this->resolveTo(['93.184.216.34']);

        $this->authorize()->assertOk();

        $this->assertSame('', $this->requestOptions[0]['proxy']);
    }

    public function testAllowingPrivateNetworksLiftsTheAddressRule()
    {
        Passport::clientMetadataDocuments(allowPrivateNetworks: true);
        $this->publish();
        $this->resolveTo(['10.0.0.5']);

        $this->authorize()->assertOk();

        $this->assertSame([], $this->lookups);
        $this->assertArrayNotHasKey(CURLOPT_RESOLVE, $this->requestOptions[0]['curl']);
        $this->assertSame('', $this->requestOptions[0]['proxy']);
    }

    public function testAllowingPrivateNetworksLiftsNothingElse()
    {
        Passport::clientMetadataDocuments(allowPrivateNetworks: true);
        $this->publish();

        $this->get('/oauth/authorize?'.$this->authorizationQuery('http://client.example/oauth/client.json'))->assertStatus(401);
        $this->get('/oauth/authorize?'.$this->authorizationQuery('https://client.example:8443/oauth/client.json#x'))->assertStatus(401);

        $this->publish($this->document(['token_endpoint_auth_method' => 'private_key_jwt']));
        $this->assertRefused($this->authorize());
        $this->assertSame(0, Client::query()->count());
    }

    public function testWithAProxyTheFetchGoesThroughItAndTheAddressCheckIsLeftToTheProxy()
    {
        Passport::clientMetadataDocuments(proxy: 'http://proxy.example:3128');
        $this->publish();
        $this->resolveTo(['10.0.0.5']);

        $this->authorize()->assertOk();

        $this->assertSame('http://proxy.example:3128', $this->requestOptions[0]['proxy']);
        $this->assertSame([], $this->lookups);
        $this->assertArrayNotHasKey(CURLOPT_RESOLVE, $this->requestOptions[0]['curl']);
    }

    public function testEveryFailureGivesTheSameMessageAndTheLogSaysWhich()
    {
        Log::spy();
        $this->publish($this->document(), 404);
        $messages = [];

        // A refused address.
        $this->resolveTo(['10.0.0.5']);
        $messages[] = $this->authorize()->json();

        // A connection failure.
        $this->resolveTo(['93.184.216.34']);
        $this->failure = new ConnectionException('cURL error 7: Failed to connect to client.example port 443');
        $this->travel(1)->hour();
        $messages[] = $this->authorize()->json();

        // A timeout.
        $this->failure = new ConnectionException('cURL error 28: Operation timed out after 3001 milliseconds');
        $this->travel(1)->hour();
        $messages[] = $this->authorize()->json();

        // A non-200 answer.
        $this->failure = null;
        $this->publish('', 503);
        $this->travel(1)->hour();
        $messages[] = $this->authorize()->json();

        $this->assertCount(1, array_unique(array_map('json_encode', $messages)));
        $this->assertSame('invalid_client', $messages[0]['error']);

        foreach (['non-public address', 'could not be fetched', 'timed out', 'status 503'] as $reason) {
            Log::shouldHaveReceived('warning')->withArgs(
                fn (string $message, array $context): bool => str_contains($message, $reason) && $context === ['host' => 'client.example']
            )->once();
        }
    }
}

class UnpinnableNetwork extends Network
{
    public function canPin(): bool
    {
        return false;
    }
}
