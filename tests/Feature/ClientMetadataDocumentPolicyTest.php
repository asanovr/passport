<?php

namespace Laravel\Passport\Tests\Feature;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Laravel\Passport\Client;
use Laravel\Passport\Database\Factories\ClientFactory;
use Laravel\Passport\Passport;
use PHPUnit\Framework\Attributes\DataProvider;
use Workbench\Database\Factories\UserFactory;

class ClientMetadataDocumentPolicyTest extends PassportTestCase
{
    use InteractsWithClientMetadataDocuments;

    protected function setUp(): void
    {
        parent::setUp();

        Route::get('/login', fn () => '')->name('login');

        Passport::tokensCan(['create' => 'Create', 'read' => 'Read']);
        Passport::authorizationView(fn ($params) => $params);
        Passport::clientMetadataDocuments();

        Http::preventStrayRequests();
    }

    protected function authorize(?string $url = null, array $overrides = [])
    {
        return $this->get('/oauth/authorize?'.$this->authorizationQuery($url, $overrides));
    }

    public function testAGuestIsSentToSignInBeforeAnythingIsFetched()
    {
        $this->publish();

        $response = $this->authorize();

        $response->assertSessionHas('promptedForLogin', true);
        $response->assertRedirectToRoute('login');
        $this->assertSame(0, $this->requestsSent());
        $this->assertSame(0, Client::query()->count());
    }

    public function testAGuestIsTreatedAsAGuestOfAnOrdinaryClientIs()
    {
        $this->publish();
        $client = ClientFactory::new()->asPublic()->create();

        $ordinary = $this->authorize($client->getKey(), ['redirect_uri' => $client->redirect_uris[0]]);
        $document = $this->authorize();

        $this->assertSame($ordinary->getStatusCode(), $document->getStatusCode());
        $this->assertSame($ordinary->headers->get('Location'), $document->headers->get('Location'));
    }

    public function testTheSameRequestFetchesAfterSigningIn()
    {
        $this->publish();

        $this->authorize()->assertRedirectToRoute('login');
        $this->assertSame(0, $this->requestsSent());

        $this->actingAs(UserFactory::new()->create(), 'web');

        $this->authorize()->assertOk()->assertJsonPath('client.name', 'Example Agent');
        $this->assertSame(1, $this->requestsSent());
    }

    public function testAGuestUsesAFreshCachedDocumentLikeAnOrdinaryClient()
    {
        $this->publish();
        $this->actingAs(UserFactory::new()->create(), 'web');
        $this->authorize()->assertOk();
        $this->app['auth']->guard('web')->logout();

        $this->authorize()->assertRedirectToRoute('login');

        $this->assertSame(1, $this->requestsSent());
    }

    public function testAGuestWithPromptNoneGetsLoginRequiredWithoutARedirectAndNothingIsFetched()
    {
        $this->publish();

        $response = $this->authorize(overrides: ['prompt' => 'none']);

        $response->assertStatus(401);
        $response->assertHeaderMissing('Location');
        $this->assertSame('login_required', $response->json('error'));
        $this->assertSame(0, $this->requestsSent());
        $this->assertSame(0, Client::query()->count());
    }

    public function testAGuestWithPromptNoneAndAFreshCopyGetsTheOrdinaryRedirect()
    {
        $this->publish();
        $this->actingAs(UserFactory::new()->create(), 'web');
        $this->authorize()->assertOk();
        $this->app['auth']->guard('web')->logout();

        $response = $this->authorize(overrides: ['prompt' => 'none']);

        $response->assertRedirect();
        $this->assertStringStartsWith('https://client.example/callback?', $response->headers->get('Location'));
        $this->assertStringContainsString('error=login_required', $response->headers->get('Location'));
    }

    public function testAGuestFetchesWhenAuthenticationIsNotRequired()
    {
        Passport::clientMetadataDocuments(requireAuthentication: false);
        $this->publish();

        $response = $this->authorize();

        $response->assertRedirectToRoute('login');
        $this->assertSame(1, $this->requestsSent());
        $this->assertSame(1, Client::query()->count());
    }

    /**
     * @return array<string, array{0: string[], 1: string, 2: bool}>
     */
    public static function hosts(): array
    {
        return [
            'an exact host' => [['example.com'], 'https://example.com/oauth/client.json', true],
            'another host' => [['example.com'], 'https://other.com/oauth/client.json', false],
            'a subdomain of an exact host' => [['example.com'], 'https://a.example.com/oauth/client.json', false],
            'an exact host in capitals' => [['Example.COM'], 'https://example.com/oauth/client.json', true],
            'a wildcard and a subdomain' => [['*.example.com'], 'https://a.example.com/oauth/client.json', true],
            'a wildcard and a deeper subdomain' => [['*.example.com'], 'https://a.b.example.com/oauth/client.json', true],
            'a wildcard and the apex' => [['*.example.com'], 'https://example.com/oauth/client.json', false],
            'a wildcard and a lookalike' => [['*.example.com'], 'https://badexample.com/oauth/client.json', false],
            'a wildcard and a suffix lookalike' => [['*.example.com'], 'https://a.example.com.evil.test/oauth/client.json', false],
            'one of several' => [['other.com', '*.example.com'], 'https://x.example.com/oauth/client.json', true],
            'no list' => [[], 'https://anything.test/oauth/client.json', true],
        ];
    }

    /**
     * @param  string[]  $allowedHosts
     */
    #[DataProvider('hosts')]
    public function testOnlyAllowedHostsAreFetched(array $allowedHosts, string $url, bool $allowed)
    {
        Passport::clientMetadataDocuments(allowedHosts: $allowedHosts);
        $this->publish($this->document(url: $url), url: $url);
        $this->actingAs(UserFactory::new()->create(), 'web');

        $response = $this->authorize($url);

        if ($allowed) {
            $response->assertOk();
            $this->assertSame(1, $this->requestsSent());
        } else {
            $response->assertStatus(401)->assertJsonPath('error', 'invalid_client');
            $this->assertSame(0, $this->requestsSent());
            $this->assertSame(0, Client::query()->count());
        }
    }

    public function testTheHookReceivesTheValidatedDocumentAndItsAddress()
    {
        $received = [];
        Passport::validateClientMetadataDocumentsUsing(function (array $document, string $url) use (&$received) {
            $received[] = [$document, $url];
        });
        $this->publish($this->document(['client_uri' => 'https://client.example/']));
        $this->actingAs(UserFactory::new()->create(), 'web');

        $this->authorize()->assertOk();

        $this->assertSame([[
            [
                'client_id' => $this->documentUrl,
                'client_name' => 'Example Agent',
                'redirect_uris' => ['https://client.example/callback'],
                'client_uri' => 'https://client.example/',
            ],
            $this->documentUrl,
        ]], $received);
    }

    public function testTheHookIsNotCalledForADocumentThatPassportRefuses()
    {
        $called = false;
        Passport::validateClientMetadataDocumentsUsing(function () use (&$called) {
            $called = true;
        });
        $this->publish($this->document(['client_secret' => 'shh']));
        $this->actingAs(UserFactory::new()->create(), 'web');

        $this->authorize()->assertStatus(401);

        $this->assertFalse($called);
    }

    public function testAReasonFromTheHookRefusesTheDocumentAndWritesNothing()
    {
        Log::spy();
        Passport::validateClientMetadataDocumentsUsing(fn (array $document) => 'look-alike host');
        $this->publish();
        $this->actingAs(UserFactory::new()->create(), 'web');

        $response = $this->authorize();

        $response->assertStatus(401);
        $this->assertSame('invalid_client', $response->json('error'));
        $this->assertSame("The client's metadata document could not be used.", $response->json('error_description'));
        $this->assertSame(0, Client::query()->count());
        Log::shouldHaveReceived('warning')->withArgs(
            fn (string $message, array $context): bool => str_contains($message, 'look-alike host') && $context === ['host' => 'client.example']
        )->once();
    }

    public function testAReasonFromTheHookDoesNotUpdateAnExistingClientAndIsNotCached()
    {
        $this->publish();
        $this->actingAs(UserFactory::new()->create(), 'web');
        $this->authorize()->assertOk();

        $this->travel(11)->minutes();
        Passport::validateClientMetadataDocumentsUsing(fn (array $document) => 'no');
        $this->publish($this->document(['client_name' => 'Renamed']));
        $this->authorize()->assertStatus(401);
        $this->assertSame('Example Agent', Client::query()->sole()->name);

        // Nothing is cached, so once the application accepts the document the next allowed attempt succeeds.
        Passport::validateClientMetadataDocumentsUsing(null);
        $this->travel(1)->minute();
        $this->authorize()->assertOk()->assertJsonPath('client.name', 'Renamed');
    }

    public function testReturningNothingFromTheHookProceeds()
    {
        Passport::validateClientMetadataDocumentsUsing(fn (array $document) => null);
        $this->publish();
        $this->actingAs(UserFactory::new()->create(), 'web');

        $this->authorize()->assertOk();
        $this->assertSame(1, Client::query()->count());
    }
}
