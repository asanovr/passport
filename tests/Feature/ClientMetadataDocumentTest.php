<?php

namespace Laravel\Passport\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Laravel\Passport\Client;
use Laravel\Passport\Database\Factories\ClientFactory;
use Laravel\Passport\Http\Middleware\CheckToken;
use Laravel\Passport\Passport;
use Orchestra\Testbench\Concerns\WithLaravelMigrations;
use RuntimeException;

class ClientMetadataDocumentTest extends PassportTestCase
{
    use InteractsWithClientMetadataDocuments;
    use WithLaravelMigrations;

    protected function setUp(): void
    {
        parent::setUp();

        Passport::tokensCan([
            'create' => 'Create',
            'read' => 'Read',
        ]);

        Passport::authorizationView(fn ($params) => $params);

        Http::preventStrayRequests();
    }

    public function testDocumentsAreNotAcceptedByDefault()
    {
        $this->publish();
        $this->signIn();

        $this->assertFalse(Passport::clientMetadataDocumentsEnabled());

        $response = $this->get('/oauth/authorize?'.$this->authorizationQuery());

        $response->assertStatus(401);
        $this->assertSame('invalid_client', $response->json('error'));
        $this->assertSame(0, $this->requestsSent());
        $this->assertSame(0, Client::query()->count());
    }

    public function testDocumentsAreNotAcceptedByASchemaWithoutTheColumn()
    {
        Schema::table('oauth_clients', function ($table) {
            $table->dropUnique(['metadata_document_url']);
            $table->dropColumn('metadata_document_url');
        });

        $this->publish();
        $this->signIn();

        $queries = [];
        DB::listen(function ($query) use (&$queries) {
            $queries[] = $query->sql;
        });

        $this->get('/oauth/authorize?'.$this->authorizationQuery())->assertStatus(401);

        $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->documentUrl,
            'redirect_uri' => 'https://client.example/callback',
            'code' => 'foo',
            'code_verifier' => $this->codeVerifier,
        ])->assertStatus(401);

        $this->assertSame(0, $this->requestsSent());
        $this->assertSame([], array_values(array_filter(
            $queries, fn (string $sql): bool => str_contains($sql, 'metadata_document_url')
        )));
    }

    public function testTheModeCanBeSwitchedOnAndOff()
    {
        $this->assertFalse(Passport::clientMetadataDocumentsEnabled());

        Passport::clientMetadataDocuments();
        $this->assertTrue(Passport::clientMetadataDocumentsEnabled());

        Passport::clientMetadataDocuments(false);
        $this->assertFalse(Passport::clientMetadataDocumentsEnabled());
    }

    public function testSwitchingTheModeOnWithoutTheColumnRaisesAClearError()
    {
        Schema::table('oauth_clients', function ($table) {
            $table->dropUnique(['metadata_document_url']);
            $table->dropColumn('metadata_document_url');
        });

        Passport::clientMetadataDocuments();
        $this->publish();
        $this->signIn();
        $this->withoutExceptionHandling();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('[metadata_document_url]');

        $this->get('/oauth/authorize?'.$this->authorizationQuery());
    }

    public function testAnAddressBecomesAClientThatCompletesTheAuthorizationCodeFlow()
    {
        Passport::clientMetadataDocuments();
        $this->publish($this->document(['client_name' => 'Example Agent']));
        $this->signIn();

        $response = $this->get('/oauth/authorize?'.$this->authorizationQuery());

        $response->assertOk();
        $this->assertSame('Example Agent', $response->json('client.name'));
        $this->assertSame(1, $this->requestsSent());

        $client = Client::query()->sole();
        $this->assertSame($this->documentUrl, $client->metadata_document_url);
        $this->assertNotSame($this->documentUrl, $client->getKey());
        $this->assertSame('Example Agent', $client->name);
        $this->assertSame(['https://client.example/callback'], $client->redirect_uris);
        $this->assertSame(['authorization_code', 'refresh_token'], $client->grant_types);
        $this->assertFalse($client->confidential());
        $this->assertFalse($client->revoked);

        $response = $this->post('/oauth/authorize', ['auth_token' => $response->json('authToken')]);

        $response->assertRedirect();
        parse_str(parse_url($response->headers->get('Location'), PHP_URL_QUERY), $params);
        $this->assertArrayHasKey('code', $params);
    }

    public function testTheCodeIsExchangedAndRefreshedWithTheAddressAndWithoutAFetch()
    {
        Passport::clientMetadataDocuments();
        $this->publish();
        $user = $this->signIn();

        $tokens = $this->connect();

        $this->assertSame(1, $this->requestsSent());
        $client = Client::query()->sole();

        Route::get('/foo', fn (Request $request) => $request->user()->currentAccessToken()->toJson())
            ->middleware(['auth:api', CheckToken::using('create')]);

        $json = $this->withToken($tokens['access_token'])->get('/foo')->assertOk()->json();

        $this->assertSame($client->getKey(), $json['oauth_client_id']);
        $this->assertEquals($user->getAuthIdentifier(), $json['oauth_user_id']);
        $this->assertSame(['create', 'read'], $json['oauth_scopes']);

        $refreshed = $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $this->documentUrl,
            'refresh_token' => $tokens['refresh_token'],
            'scope' => 'create read',
        ])->assertOk()->json();

        $this->assertNotSame($tokens['refresh_token'], $refreshed['refresh_token']);
        $this->assertNotSame($tokens['access_token'], $refreshed['access_token']);
        $this->assertSame(1, $this->requestsSent());

        $this->withToken($refreshed['access_token'])->get('/foo')->assertOk();
    }

    public function testTheBareIdOfADocumentIdentifiedClientIsRefused()
    {
        Passport::clientMetadataDocuments();
        $this->publish();
        $this->signIn();

        $tokens = $this->connect();
        $client = Client::query()->sole();

        $this->get('/oauth/authorize?'.$this->authorizationQuery($client->getKey()))
            ->assertStatus(401)
            ->assertJsonPath('error', 'invalid_client');

        $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $client->getKey(),
            'refresh_token' => $tokens['refresh_token'],
        ])->assertStatus(401)->assertJsonPath('error', 'invalid_client');

        Route::get('/foo', fn (Request $request) => $request->user()->currentAccessToken()->toJson())
            ->middleware(['auth:api', CheckToken::using('create', 'read')]);

        $this->withToken($tokens['access_token'])->get('/foo')->assertOk();
    }

    public function testARevokedClientIsRefusedAndNeverRevivedByAFetch()
    {
        Passport::clientMetadataDocuments();
        $this->publish();
        $this->signIn();

        $tokens = $this->connect();
        Client::query()->sole()->forceFill(['revoked' => true])->save();

        $this->get('/oauth/authorize?'.$this->authorizationQuery())->assertStatus(401);
        $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $this->documentUrl,
            'refresh_token' => $tokens['refresh_token'],
        ])->assertStatus(401)->assertJsonPath('error', 'invalid_client');

        $this->assertSame(1, $this->requestsSent());
        $this->assertTrue(Client::query()->sole()->revoked);
        $this->assertSame(1, Client::query()->count());
    }

    public function testAClientThatIsRevokedWhileItsDocumentIsFetchedStaysRevoked()
    {
        Passport::clientMetadataDocuments();
        $this->signIn();

        Http::fake(function () {
            Client::query()->forceCreate([
                'name' => 'Revoked',
                'redirect_uris' => ['https://client.example/old'],
                'grant_types' => ['authorization_code'],
                'revoked' => true,
                'metadata_document_url' => $this->documentUrl,
            ]);

            return Http::response($this->document(['client_name' => 'Renamed']), 200, ['Content-Type' => 'application/json']);
        });

        $this->get('/oauth/authorize?'.$this->authorizationQuery())->assertStatus(401);

        $client = Client::query()->sole();
        $this->assertTrue($client->revoked);
        $this->assertSame('Revoked', $client->name);
    }

    public function testAChangedDocumentUpdatesTheSameClientBeforeTheConsentViewReadsIt()
    {
        Passport::clientMetadataDocuments();
        $this->publish();
        $this->signIn();

        $this->get('/oauth/authorize?'.$this->authorizationQuery())->assertOk();
        $id = Client::query()->sole()->getKey();

        $this->travel(11)->minutes();
        $this->publish($this->document([
            'client_name' => 'Renamed Agent',
            'redirect_uris' => ['https://client.example/callback', 'https://client.example/other'],
        ]));

        $response = $this->get('/oauth/authorize?'.$this->authorizationQuery(overrides: [
            'redirect_uri' => 'https://client.example/other',
        ]))->assertOk();

        $this->assertSame('Renamed Agent', $response->json('client.name'));
        $this->assertSame($id, $response->json('client.id'));
        $this->assertSame(1, Client::query()->count());
        $this->assertSame(
            ['https://client.example/callback', 'https://client.example/other'],
            Client::query()->sole()->redirect_uris
        );
    }

    public function testTwoFirstFetchesRacingEndWithOneClient()
    {
        Passport::clientMetadataDocuments();
        $this->signIn();

        Http::fake(function () {
            Client::query()->forceCreate([
                'name' => 'Raced',
                'redirect_uris' => ['https://client.example/old'],
                'grant_types' => ['authorization_code', 'refresh_token'],
                'revoked' => false,
                'metadata_document_url' => $this->documentUrl,
            ]);

            return Http::response($this->document(), 200, ['Content-Type' => 'application/json']);
        });

        $this->get('/oauth/authorize?'.$this->authorizationQuery())->assertOk();

        $client = Client::query()->sole();
        $this->assertSame('Example Agent', $client->name);
        $this->assertSame(['https://client.example/callback'], $client->redirect_uris);
    }

    public function testTwoFirstFetchesRacingEndWithOneClientInsideATransaction()
    {
        Passport::clientMetadataDocuments();
        $this->signIn();

        Http::fake(function () {
            Client::query()->forceCreate([
                'name' => 'Raced',
                'redirect_uris' => ['https://client.example/old'],
                'grant_types' => ['authorization_code', 'refresh_token'],
                'revoked' => false,
                'metadata_document_url' => $this->documentUrl,
            ]);

            return Http::response($this->document(), 200, ['Content-Type' => 'application/json']);
        });

        DB::transaction(function () {
            $this->get('/oauth/authorize?'.$this->authorizationQuery())->assertOk();
        });

        $this->assertSame(1, Client::query()->count());
        $this->assertSame('Example Agent', Client::query()->sole()->name);
    }

    public function testADocumentIdentifiedClientIsNeverFirstParty()
    {
        $this->assertTrue(ClientFactory::new()->asPublic()->create()->firstParty());

        $this->assertFalse(ClientFactory::new()->asPublic()->create([
            'metadata_document_url' => $this->documentUrl,
        ])->firstParty());
    }

    public function testRefusalsAreJsonInvalidClientErrorsWithoutARedirect()
    {
        Passport::clientMetadataDocuments();
        $this->publish(['client_id' => 'https://client.example/somewhere/else.json', 'redirect_uris' => ['https://x.test/cb']]);
        $this->signIn();

        $response = $this->get('/oauth/authorize?'.$this->authorizationQuery());

        $response->assertStatus(401);
        $response->assertHeaderMissing('Location');
        $this->assertSame('invalid_client', $response->json('error'));
        $this->assertSame("The client's metadata document could not be used.", $response->json('error_description'));
        $this->assertSame(0, Client::query()->count());
    }

    public function testOrdinaryClientsAreUnaffectedWhileTheModeIsOn()
    {
        Passport::clientMetadataDocuments();
        $client = ClientFactory::new()->asPublic()->create();
        $this->signIn();

        $this->get('/oauth/authorize?'.$this->authorizationQuery($client->getKey(), [
            'redirect_uri' => $client->redirect_uris[0],
        ]))->assertOk()->assertJsonPath('client.id', $client->getKey());

        $this->assertSame(0, $this->requestsSent());
    }
}
