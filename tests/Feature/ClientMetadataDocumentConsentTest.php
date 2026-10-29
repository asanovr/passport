<?php

namespace Laravel\Passport\Tests\Feature;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Http;
use Laravel\Passport\Client;
use Laravel\Passport\Database\Factories\ClientFactory;
use Laravel\Passport\Passport;
use PHPUnit\Framework\Attributes\DataProvider;

class ClientMetadataDocumentConsentTest extends PassportTestCase
{
    use InteractsWithClientMetadataDocuments;

    protected function setUp(): void
    {
        parent::setUp();

        Passport::tokensCan(['create' => 'Create', 'read' => 'Read']);
        Passport::authorizationView(fn ($params) => $params);
        Passport::clientMetadataDocuments();

        Http::preventStrayRequests();

        $this->signIn();
    }

    protected function tearDown(): void
    {
        Passport::useClientModel(Client::class);

        parent::tearDown();
    }

    /**
     * Get the "clientMetadata" value of an authorization request.
     *
     * @param  array<string, mixed>  $overrides
     * @return array<string, mixed>|null
     */
    protected function consent(array $overrides = []): ?array
    {
        return $this->authorize(null, $overrides)->assertOk()->json('clientMetadata');
    }

    public function testTheViewReceivesTheDocumentsData()
    {
        $this->publish($this->document([
            'client_uri' => 'https://client.example/about',
            'logo_uri' => 'https://cdn.client.example/logo.png',
            'redirect_uris' => ['https://client.example/callback', 'http://127.0.0.1/callback'],
        ]));

        $this->assertSame([
            'url' => $this->documentUrl,
            'host' => 'client.example',
            'name' => 'Example Agent',
            'clientUri' => 'https://client.example/about',
            'clientUriMatchesOrigin' => true,
            'logoUri' => 'https://cdn.client.example/logo.png',
            'redirectIsLoopback' => false,
            'allRedirectsAreLoopback' => false,
        ], $this->consent());
    }

    public function testTheWebsiteOnAnotherOriginDoesNotMatch()
    {
        $this->publish($this->document(['client_uri' => 'https://www.client.example/']));
        $this->assertFalse($this->consent()['clientUriMatchesOrigin']);
    }

    public function testTheWebsiteOnAnotherSchemeOrPortDoesNotMatch()
    {
        Passport::clientMetadataDocuments(allowPrivateNetworks: true);
        $this->publish($this->document(['client_uri' => 'https://client.example:8443/']));
        $this->assertFalse($this->consent()['clientUriMatchesOrigin']);
    }

    public function testWithoutAWebsiteNothingMatches()
    {
        $this->publish();

        $consent = $this->consent();

        $this->assertNull($consent['clientUri']);
        $this->assertNull($consent['logoUri']);
        $this->assertFalse($consent['clientUriMatchesOrigin']);
    }

    public function testTheNameIsTheHostWhenTheDocumentHasNone()
    {
        $this->publish($this->document(['client_name' => static::MISSING]));

        $this->assertSame('client.example', $this->consent()['name']);
    }

    public function testTheRequestsRedirectAddressIsReportedAsLoopbackOrNot()
    {
        $this->publish($this->document(['redirect_uris' => ['https://client.example/callback', 'http://127.0.0.1/callback', 'http://[::1]/callback']]));

        $this->assertFalse($this->consent(['redirect_uri' => 'https://client.example/callback'])['redirectIsLoopback']);
        $this->assertTrue($this->consent(['redirect_uri' => 'http://127.0.0.1:4000/callback'])['redirectIsLoopback']);
        $this->assertTrue($this->consent(['redirect_uri' => 'http://[::1]:4000/callback'])['redirectIsLoopback']);
    }

    public function testEveryListedRedirectAddressBeingLoopbackIsReported()
    {
        $this->publish($this->document(['redirect_uris' => ['http://127.0.0.1/callback', 'http://localhost/callback']]));

        $this->assertTrue($this->consent(['redirect_uri' => 'http://127.0.0.1:4000/callback'])['allRedirectsAreLoopback']);
    }

    public function testTheOnlyListedRedirectAddressIsTheEffectiveOneWhenTheRequestOmitsIt()
    {
        $this->publish($this->document(['redirect_uris' => ['http://127.0.0.1:4000/callback']]));

        $consent = $this->authorize(null, ['redirect_uri' => null])->assertOk()->json('clientMetadata');

        $this->assertTrue($consent['redirectIsLoopback']);
        $this->assertTrue($consent['allRedirectsAreLoopback']);

        $this->publish($this->document(['redirect_uris' => ['https://client.example/callback']]), url: $this->documentUrl);
        $this->travel(11)->minutes();

        $this->assertFalse($this->authorize(null, ['redirect_uri' => null])->assertOk()->json('clientMetadata.redirectIsLoopback'));
    }

    public function testAnOrdinaryClientHasNoClientMetadata()
    {
        $client = ClientFactory::new()->asPublic()->create();

        $response = $this->authorize($client->getKey(), ['redirect_uri' => $client->redirect_uris[0]])->assertOk();

        $this->assertArrayNotHasKey('clientMetadata', $response->json());
    }

    /**
     * Connect once with an https redirect address, so that the person has a live token.
     */
    protected function connectOnce(): void
    {
        $this->publish($this->document(['redirect_uris' => ['https://client.example/callback', 'http://127.0.0.1/callback']]));
        $this->connect();
    }

    public function testALiveTokenIsNotEnoughForALoopbackRedirectButIsForAnHttpsOne()
    {
        $this->connectOnce();

        $this->authorize(null, ['redirect_uri' => 'https://client.example/callback'])
            ->assertRedirect()
            ->assertSessionMissing('authRequest');

        $this->authorize(null, ['redirect_uri' => 'http://127.0.0.1:4000/callback'])
            ->assertOk()
            ->assertSessionHas('authRequest')
            ->assertJsonPath('clientMetadata.redirectIsLoopback', true);
    }

    #[DataProvider('disguisedLoopbackRedirects')]
    public function testALiveTokenIsNotEnoughForADisguisedLoopbackRedirect(string $redirect)
    {
        $this->publish($this->document(['redirect_uris' => [
            'https://client.example/callback', 'http://127.0.0.1/callback', 'http://localhost/callback',
        ]]));
        $this->connect();

        $this->authorize(null, ['redirect_uri' => $redirect])
            ->assertOk()
            ->assertSessionHas('authRequest')
            ->assertJsonPath('clientMetadata.redirectIsLoopback', true);
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function disguisedLoopbackRedirects(): array
    {
        return [
            'a percent-encoded letter' => ['http://loc%61lhost:5555/callback'],
            'a circled letter' => ['http://ⓛocalhost:5555/callback'],
            'a percent-encoded address' => ['http://%31%32%37.0.0.1:5555/callback'],
        ];
    }

    public function testTheFirstPartyPatternDoesNotApproveADocumentIdentifiedClientSilently()
    {
        Passport::useClientModel(SkipsAuthorizationClient::class);
        $this->publish();

        $this->authorize()->assertOk()->assertSessionHas('authRequest');
        $this->assertFalse(Passport::client()->newQuery()->sole()->firstParty());
    }

    public function testOrdinaryClientsKeepSkippingAuthorizationAndReusingGrants()
    {
        Passport::useClientModel(SkipsAuthorizationClient::class);
        $client = ClientFactory::new()->asPublic()->create(['redirect_uris' => ['http://127.0.0.1/callback']]);

        $this->authorize($client->getKey(), ['redirect_uri' => 'http://127.0.0.1:4000/callback'])
            ->assertRedirect()
            ->assertSessionMissing('authRequest');
    }

    public function testAnOrdinaryClientWithALiveTokenIsStillApprovedSilentlyOnLoopback()
    {
        $client = ClientFactory::new()->asPublic()->create(['redirect_uris' => ['http://127.0.0.1/callback']]);
        $user = $this->signIn();
        $client->tokens()->forceCreate([
            'id' => 'token', 'user_id' => $user->getAuthIdentifier(), 'client_id' => $client->getKey(),
            'scopes' => ['create', 'read'], 'revoked' => false, 'expires_at' => now()->addDay(),
        ]);

        $this->authorize($client->getKey(), ['redirect_uri' => 'http://127.0.0.1:4000/callback'])
            ->assertRedirect()
            ->assertSessionMissing('authRequest');
    }

    public function testACustomClientModelCanReuseGrantsOnLoopback()
    {
        Passport::useClientModel(ReusingClient::class);
        $this->connectOnce();

        $this->authorize(null, ['redirect_uri' => 'http://127.0.0.1:4000/callback'])
            ->assertRedirect()
            ->assertSessionMissing('authRequest');
    }

    public function testACustomClientModelCanRefuseToReuseGrantsOfOrdinaryClients()
    {
        Passport::useClientModel(NeverReusingClient::class);
        $client = ClientFactory::new()->asPublic()->create();
        $user = $this->signIn();
        $client->tokens()->forceCreate([
            'id' => 'token', 'user_id' => $user->getAuthIdentifier(), 'client_id' => $client->getKey(),
            'scopes' => ['create', 'read'], 'revoked' => false, 'expires_at' => now()->addDay(),
        ]);

        $this->authorize($client->getKey(), ['redirect_uri' => $client->redirect_uris[0]])
            ->assertOk()
            ->assertSessionHas('authRequest');
    }

    /**
     * @return array<string, array{0: string[], 1: string, 2: bool}>
     */
    public static function localhostRedirects(): array
    {
        return [
            'any port' => [['http://localhost/callback'], 'http://localhost:54321/callback', true],
            'a different path' => [['http://localhost/callback'], 'http://localhost:54321/other', false],
            'an added query' => [['http://localhost/callback'], 'http://localhost:54321/callback?a=1', false],
            'a different host' => [['http://localhost/callback'], 'http://localhost.evil.test:54321/callback', false],
            'a name below localhost on another port' => [['http://app.localhost/callback'], 'http://app.localhost:54321/callback', false],
            'a loopback address instead of the name' => [['http://localhost/callback'], 'http://127.0.0.1:54321/callback', false],
            'https instead of http' => [['http://localhost/callback'], 'https://localhost:54321/callback', false],
            'https on another port when https is listed' => [['https://localhost/callback'], 'https://localhost:8443/callback', false],
            'user information' => [['http://localhost/callback'], 'http://user@localhost:54321/callback', false],
            'a port that is not a number' => [['http://localhost/callback'], 'http://localhost:abc/callback', false],
            'the same query on any port' => [['http://localhost/callback?x=1'], 'http://localhost:54321/callback?x=1', true],
            'a different query' => [['http://localhost/callback?x=1'], 'http://localhost:54321/callback?x=2', false],
            'another port than the listed one' => [['http://localhost:8080/callback'], 'http://localhost:8081/callback', true],
            'localhost when only the loopback address is listed' => [['http://127.0.0.1/callback'], 'http://localhost:54321/callback', false],
            'the loopback IPv4 address on any port' => [['http://127.0.0.1/callback'], 'http://127.0.0.1:9999/callback', true],
            'an https address that is listed' => [['https://client.example/callback'], 'https://client.example/callback', true],
        ];
    }

    /**
     * @param  string[]  $listed
     */
    #[DataProvider('localhostRedirects')]
    public function testLoopbackRedirectsOfADocumentIdentifiedClient(array $listed, string $requested, bool $accepted)
    {
        $this->publish($this->document(['redirect_uris' => $listed]));

        $response = $this->authorize(null, ['redirect_uri' => $requested]);

        if (! $accepted) {
            $response->assertStatus(401)->assertJsonPath('error', 'invalid_client');

            return;
        }

        $response->assertOk();
        $approved = $this->post('/oauth/authorize', ['auth_token' => $response->json('authToken')])->assertRedirect();

        $this->assertStringStartsWith($requested.(str_contains($requested, '?') ? '&' : '?'), $approved->headers->get('Location'));

        parse_str(parse_url($approved->headers->get('Location'), PHP_URL_QUERY), $params);

        $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->documentUrl,
            'redirect_uri' => $requested,
            'code' => $params['code'],
            'code_verifier' => $this->codeVerifier,
        ])->assertOk()->assertJsonStructure(['access_token', 'refresh_token']);
    }

    public function testTheCodeExchangeStillNeedsTheRedirectAddressThatWasRequested()
    {
        $this->publish($this->document(['redirect_uris' => ['http://localhost/callback']]));

        $response = $this->authorize(null, ['redirect_uri' => 'http://localhost:54321/callback'])->assertOk();
        $approved = $this->post('/oauth/authorize', ['auth_token' => $response->json('authToken')]);
        parse_str(parse_url($approved->headers->get('Location'), PHP_URL_QUERY), $params);

        $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->documentUrl,
            'redirect_uri' => 'http://localhost:54322/callback',
            'code' => $params['code'],
            'code_verifier' => $this->codeVerifier,
        ])->assertStatus(400);
    }

    public function testOrdinaryClientsKeepLeaguesMatchingForLocalhost()
    {
        $client = ClientFactory::new()->asPublic()->create(['redirect_uris' => ['http://localhost/callback']]);

        $this->authorize($client->getKey(), ['redirect_uri' => 'http://localhost:54321/callback'])
            ->assertStatus(401)
            ->assertJsonPath('error', 'invalid_client');

        $this->authorize($client->getKey(), ['redirect_uri' => 'http://localhost/callback'])->assertOk();
    }

    public function testTheLocalhostPortRuleStopsWhenLoopbackRedirectsAreNotAllowed()
    {
        $this->publish($this->document(['redirect_uris' => ['http://localhost/callback']]));
        $this->authorize(null, ['redirect_uri' => 'http://localhost:54321/callback'])->assertOk();

        Passport::clientMetadataDocuments(allowLoopbackRedirects: false);

        $this->authorize(null, ['redirect_uri' => 'http://localhost:54321/callback'])
            ->assertStatus(401)
            ->assertJsonPath('error', 'invalid_client');
    }

    public function testADocumentListingALoopbackRedirectIsRefusedWhenLoopbackRedirectsAreNotAllowed()
    {
        Passport::clientMetadataDocuments(allowLoopbackRedirects: false);

        foreach (['http://127.0.0.1/callback', 'http://[::1]:3000/callback', 'http://localhost/callback'] as $loopback) {
            $this->publish($this->document(['redirect_uris' => ['https://client.example/callback', $loopback]]));
            $this->authorize()->assertStatus(401)->assertJsonPath('error', 'invalid_client');
        }

        $this->assertSame(0, Client::query()->count());

        $this->publish($this->document(['redirect_uris' => ['https://client.example/callback']]));
        $this->travel(1)->hour();
        $this->authorize()->assertOk();
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function httpsLoopbackRedirects(): array
    {
        return [
            'localhost' => ['https://localhost/callback'],
            'an IPv4 loopback address' => ['https://127.0.0.1/callback'],
            'an IPv6 loopback address' => ['https://[::1]/callback'],
            'another address of 127.0.0.0/8' => ['https://127.0.0.2/callback'],
            'localhost with a trailing dot' => ['https://localhost./callback'],
            'a name below localhost' => ['https://app.localhost/callback'],
            'a name below localhost in capitals' => ['https://APP.Localhost/callback'],
            'a short IPv4 form' => ['https://127.1/callback'],
            'a decimal IPv4 form' => ['https://2130706433/callback'],
            'an IPv4-mapped IPv6 loopback address' => ['https://[::ffff:127.0.0.1]/callback'],
            'a percent-encoded letter' => ['https://loc%61lhost/callback'],
            'a circled letter' => ['https://ⓛocalhost/callback'],
            'a percent-encoded address' => ['https://%31%32%37.0.0.1/callback'],
        ];
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function hostsThatAreNotLoopback(): array
    {
        return [
            'a name that contains localhost' => ['https://notlocalhost.example/callback'],
            'a name that starts with localhost' => ['https://localhost.example/callback'],
            'an address next to 127.0.0.0/8' => ['https://128.0.0.1/callback'],
            'an address that starts with 127' => ['https://127.0.0.1.example/callback'],
            'another IPv6 address' => ['https://[::2]/callback'],
            'a short IPv4 form outside 127.0.0.0/8' => ['https://128.1/callback'],
            'an IPv4-mapped address outside 127.0.0.0/8' => ['https://[::ffff:10.0.0.1]/callback'],
        ];
    }

    #[DataProvider('hostsThatAreNotLoopback')]
    public function testOtherHostsDoNotCountAsLoopback(string $redirect)
    {
        $this->publish($this->document(['redirect_uris' => [$redirect]]));

        $consent = $this->consent(['redirect_uri' => $redirect]);

        $this->assertFalse($consent['redirectIsLoopback']);
        $this->assertFalse($consent['allRedirectsAreLoopback']);
    }

    #[DataProvider('httpsLoopbackRedirects')]
    public function testAnHttpsRedirectOnALoopbackHostCountsAsLoopback(string $redirect)
    {
        $this->publish($this->document(['redirect_uris' => [$redirect]]));

        $consent = $this->consent(['redirect_uri' => $redirect]);

        $this->assertTrue($consent['redirectIsLoopback']);
        $this->assertTrue($consent['allRedirectsAreLoopback']);
    }

    #[DataProvider('httpsLoopbackRedirects')]
    public function testAnHttpsRedirectOnALoopbackHostIsNeverApprovedSilently(string $redirect)
    {
        $this->publish($this->document(['redirect_uris' => ['https://client.example/callback', $redirect]]));
        $this->connect(redirectUri: $redirect);

        $this->authorize(null, ['redirect_uri' => $redirect])->assertOk()->assertSessionHas('authRequest');
    }

    #[DataProvider('httpsLoopbackRedirects')]
    public function testAnHttpsLoopbackRedirectIsRefusedWhenLoopbackRedirectsAreNotAllowed(string $redirect)
    {
        Passport::clientMetadataDocuments(allowLoopbackRedirects: false);
        $this->publish($this->document(['redirect_uris' => ['https://client.example/callback', $redirect]]));

        $this->authorize()->assertStatus(401)->assertJsonPath('error', 'invalid_client');
        $this->assertSame(0, Client::query()->count());
    }

    public function testAnHttpsRedirectOnAnotherHostIsNotLoopback()
    {
        $this->publish($this->document(['redirect_uris' => ['https://localhost.example/callback']]));

        $this->assertFalse($this->consent(['redirect_uri' => 'https://localhost.example/callback'])['redirectIsLoopback']);
    }
}

class SkipsAuthorizationClient extends Client
{
    public function skipsAuthorization(Authenticatable $user, array $scopes): bool
    {
        return $this->firstParty();
    }
}

class ReusingClient extends Client
{
    public function mayReuseGrant(?string $redirectUri): bool
    {
        return true;
    }
}

class NeverReusingClient extends Client
{
    public function mayReuseGrant(?string $redirectUri): bool
    {
        return false;
    }
}
