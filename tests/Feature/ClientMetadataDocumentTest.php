<?php

namespace Laravel\Passport\Tests\Feature;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use InvalidArgumentException;
use Laravel\Passport\Bridge\ClientRepository as BridgeClientRepository;
use Laravel\Passport\Client;
use Laravel\Passport\Database\Factories\ClientFactory;
use Laravel\Passport\Http\Middleware\CheckToken;
use Laravel\Passport\Passport;
use Orchestra\Testbench\Concerns\WithLaravelMigrations;
use PHPUnit\Framework\Attributes\DataProvider;

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

        $this->beforeApplicationDestroyed(function () {
            Model::preventAccessingMissingAttributes(false);
            Passport::useClientModel(Client::class);
        });
    }

    protected function dropTheColumn(): void
    {
        Schema::table('oauth_clients', function ($table) {
            $table->dropIndex(['metadata_document_url']);
            $table->dropColumn('metadata_document_url');
        });
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

    public function testTheModeCanBeSwitchedOnAndOff()
    {
        $this->assertFalse(Passport::clientMetadataDocumentsEnabled());

        Passport::clientMetadataDocuments();
        $this->assertTrue(Passport::clientMetadataDocumentsEnabled());

        Passport::clientMetadataDocuments(false);
        $this->assertFalse(Passport::clientMetadataDocumentsEnabled());
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

        // The copy of the document has expired, so only the refusal of a revoked client keeps it from being fetched.
        Cache::flush();
        Log::spy();

        $this->get('/oauth/authorize?'.$this->authorizationQuery())->assertStatus(401);
        $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $this->documentUrl,
            'refresh_token' => $tokens['refresh_token'],
        ])->assertStatus(401)->assertJsonPath('error', 'invalid_client');

        $this->assertSame(1, $this->requestsSent());
        $this->assertTrue(Client::query()->sole()->revoked);
        $this->assertSame(1, Client::query()->count());
        Log::shouldHaveReceived('warning')->withArgs(
            fn (string $message): bool => str_contains($message, 'the client has been revoked')
        )->once();
    }

    public function testAClientThatIsRevokedWhileItsDocumentIsFetchedStaysRevoked()
    {
        Passport::clientMetadataDocuments();
        $this->signIn();

        $this->resolveHostsAsPublic();

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

        $this->resolveHostsAsPublic();

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

        $this->resolveHostsAsPublic();

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

    /**
     * An application may add a unique index of its own, and then the database settles a race that no lock covers.
     *
     * SQLite does not abort a transaction when a statement fails, so this cannot prove that the failed insert is
     * rolled back to a savepoint, which is what keeps the request's own transaction usable on other databases.
     */
    public function testARacingRequestWithoutALockIsSettledByAUniqueIndexTheApplicationAdded()
    {
        Schema::table('oauth_clients', fn ($table) => $table->unique(['metadata_document_url']));

        Passport::clientMetadataDocuments();
        $this->publish();
        $this->signIn();

        $lookups = 0;
        $competitor = null;

        DB::listen(function ($query) use (&$lookups, &$competitor) {
            if ($competitor === null && str_contains($query->sql, '"metadata_document_url" = ?') && ++$lookups === 2) {
                $competitor = $this->record(['name' => 'Raced', 'redirect_uris' => ['https://client.example/old']]);
            }
        });

        $response = DB::transaction(
            fn () => $this->get('/oauth/authorize?'.$this->authorizationQuery())->assertOk()
        );

        $this->assertNotNull($competitor);
        $this->assertSame($competitor->getKey(), $response->json('client.id'));
        $this->assertSame(1, Client::query()->count());
        $this->assertSame('Example Agent', Client::query()->sole()->name);
    }

    public function testARequestThatCreatesARecordNextToAnOlderOneContinuesWithTheOlderAndRemovesItsOwn()
    {
        Passport::clientMetadataDocuments();
        $this->publish();
        $this->signIn();

        $lookups = 0;
        $competitor = null;

        // The other request creates its record after this one looked, and without any lock or unique index.
        DB::listen(function ($query) use (&$lookups, &$competitor) {
            if ($competitor === null && str_contains($query->sql, '"metadata_document_url" = ?') && ++$lookups === 2) {
                $competitor = $this->record(['name' => 'Raced', 'created_at' => now()->subHour()]);
            }
        });

        $response = $this->get('/oauth/authorize?'.$this->authorizationQuery())->assertOk();

        $this->assertNotNull($competitor);
        $this->assertSame($competitor->getKey(), $response->json('client.id'));
        $this->assertSame(1, Client::query()->count());
        $this->assertSame('Example Agent', Client::query()->sole()->name);
    }

    public function testTheOldestOfSeveralRecordsOfAnAddressIsTheClient()
    {
        Passport::clientMetadataDocuments();
        $this->publish();
        $this->signIn();

        // The older record is inserted second and has the larger key.
        $newer = $this->record(['id' => '00000000-0000-7000-8000-000000000000', 'created_at' => now()->addHour()]);
        $older = $this->record(['id' => 'ffffffff-ffff-7fff-bfff-ffffffffffff', 'created_at' => now()->subHour()]);

        $this->get('/oauth/authorize?'.$this->authorizationQuery())->assertOk()
            ->assertJsonPath('client.id', $older->getKey());

        $tokens = $this->connect();
        $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $this->documentUrl,
            'refresh_token' => $tokens['refresh_token'],
        ])->assertOk();

        $this->assertSame([$older->getKey()], DB::table('oauth_access_tokens')->pluck('client_id')->unique()->all());
        $this->assertSame(2, Client::query()->count());
        $this->assertSame('Example Agent', $older->refresh()->name);
        $this->assertSame('Example', $newer->refresh()->name);
    }

    public function testRecordsOfAnAddressCreatedInTheSameSecondAreToldApartByTheirKeys()
    {
        Passport::clientMetadataDocuments();
        $this->publish();
        $this->signIn();

        $at = now()->startOfSecond();
        $this->record(['id' => 'ffffffff-ffff-7fff-bfff-ffffffffffff', 'created_at' => $at]);
        $first = $this->record(['id' => '00000000-0000-7000-8000-000000000000', 'created_at' => $at]);

        $this->get('/oauth/authorize?'.$this->authorizationQuery())->assertOk()
            ->assertJsonPath('client.id', $first->getKey());
    }

    public function testARevokedRecordIsNotUnblockedByANewerActiveRecordOfTheSameAddress()
    {
        Passport::clientMetadataDocuments();
        $this->publish();
        $this->signIn();

        $tokens = $this->connect();

        Client::query()->sole()->forceFill(['revoked' => true])->save();
        $this->record(['created_at' => now()->addHour()]);

        $this->get('/oauth/authorize?'.$this->authorizationQuery())->assertStatus(401);
        $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $this->documentUrl,
            'refresh_token' => $tokens['refresh_token'],
        ])->assertStatus(401)->assertJsonPath('error', 'invalid_client');
    }

    public function testAddressesADatabaseCannotTellApartEachHaveTheirOwnRecord()
    {
        $this->useACaseInsensitiveColumn();

        $upper = 'https://client.example/OAUTH/client.json';
        $first = $this->record(['metadata_document_url' => $upper, 'created_at' => now()->subHour()]);
        $second = $this->record(['created_at' => now()]);

        Passport::clientMetadataDocuments();
        $this->publish();
        $this->publish(url: $upper);
        $this->signIn();

        $this->get('/oauth/authorize?'.$this->authorizationQuery($upper))->assertOk()
            ->assertJsonPath('client.id', $first->getKey());
        $this->get('/oauth/authorize?'.$this->authorizationQuery())->assertOk()
            ->assertJsonPath('client.id', $second->getKey());
    }

    public function testACaseVariantOfAnAddressGetsItsOwnRecordWhenNoUniqueIndexForbidsIt()
    {
        $this->useACaseInsensitiveColumn();

        $other = $this->record([
            'name' => 'Victim',
            'redirect_uris' => ['https://victim.example/callback'],
            'metadata_document_url' => 'https://client.example/OAUTH/client.json',
        ]);

        Passport::clientMetadataDocuments();
        $this->publish();
        $this->signIn();

        $response = $this->get('/oauth/authorize?'.$this->authorizationQuery())->assertOk();

        $this->assertSame(2, Client::query()->count());
        $this->assertNotSame($other->getKey(), $response->json('client.id'));
        $this->assertSame('Victim', $other->refresh()->name);
        $this->assertSame(['https://victim.example/callback'], $other->redirect_uris);
    }

    /**
     * Make the column match addresses regardless of case, as MySQL's default collation does, with a plain index.
     */
    protected function useACaseInsensitiveColumn(): void
    {
        $this->dropTheColumn();
        DB::statement('alter table oauth_clients add column metadata_document_url varchar(255) collate nocase');
        DB::statement('create index oauth_clients_metadata_document_url_index on oauth_clients (metadata_document_url)');
    }

    /**
     * Store a client that is identified by the document address.
     *
     * @param  array<string, mixed>  $attributes
     */
    protected function record(array $attributes = []): Client
    {
        return Client::query()->forceCreate(array_replace([
            'name' => 'Example',
            'secret' => null,
            'redirect_uris' => ['https://client.example/callback'],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'revoked' => false,
            'metadata_document_url' => $this->documentUrl,
        ], $attributes));
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

    public function testAnApplicationThatNeverEnabledTheModeAndLacksTheColumnCompletesOrdinaryFlowsUnderStrictModels()
    {
        $this->dropTheColumn();
        Model::preventAccessingMissingAttributes();

        $client = ClientFactory::new()->asPublic()->create(['redirect_uris' => ['https://client.example/callback']]);
        $this->signIn();

        $tokens = $this->connect($client->getKey());

        $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $client->getKey(),
            'refresh_token' => $tokens['refresh_token'],
            'scope' => 'create read',
        ])->assertOk();
    }

    public function testAnHttpsClientIdGetsLeaguesPlainErrorAndNoLogLineWhileTheModeIsOff()
    {
        Log::spy();
        $this->publish();
        $this->signIn();

        $response = $this->get('/oauth/authorize?'.$this->authorizationQuery())->assertStatus(401);

        $this->assertSame('invalid_client', $response->json('error'));
        $this->assertSame('Client authentication failed', $response->json('error_description'));
        Log::shouldNotHaveReceived('warning');
    }

    public function testTheBareIdOfADocumentIdentifiedClientIsRefusedWhileTheModeIsOff()
    {
        Passport::clientMetadataDocuments();
        $this->publish();
        $this->signIn();

        $tokens = $this->connect();
        $id = Client::query()->sole()->getKey();

        Passport::clientMetadataDocuments(false);

        $this->get('/oauth/authorize?'.$this->authorizationQuery($id))->assertStatus(401);
        $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $id,
            'refresh_token' => $tokens['refresh_token'],
        ])->assertStatus(401)->assertJsonPath('error', 'invalid_client');
    }

    public function testNothingAsksForTheColumnWhenTheModeWasNeverConfigured()
    {
        $this->dropTheColumn();
        $this->publish();
        $this->signIn();

        $this->assertNull(Passport::$clientMetadataDocuments);

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
            'code_verifier' => str_repeat('a', 64),
        ])->assertStatus(401);
        $this->post('/oauth/device/code', ['client_id' => $this->documentUrl, 'scope' => 'create'])->assertStatus(401);

        $this->assertSame([], array_values(array_filter(
            $queries, fn (string $sql): bool => str_contains($sql, 'metadata_document_url')
        )));
    }

    public function testAnHttpsShapedIdOfAnotherKindOfClientIsLookedUpAsItAlwaysWasWithoutTheColumn()
    {
        $this->dropTheColumn();
        Passport::useClientModel(UrlKeyedClient::class);

        UrlKeyedClient::query()->forceCreate([
            'id' => 'https://legacy.example/app',
            'name' => 'Legacy',
            'secret' => null,
            'redirect_uris' => ['https://legacy.example/callback'],
            'grant_types' => ['authorization_code'],
            'revoked' => false,
        ]);

        $entity = $this->app->make(BridgeClientRepository::class)->getClientEntity('https://legacy.example/app');

        $this->assertSame('https://legacy.example/app', $entity?->getIdentifier());
    }

    public function testAnHttpsShapedIdOfAnotherKindOfClientAuthorizesAsItAlwaysDidWhileTheModeIsOff()
    {
        $this->dropTheColumn();
        Passport::useClientModel(UrlKeyedClient::class);

        UrlKeyedClient::query()->forceCreate([
            'id' => 'https://legacy.example/app',
            'name' => 'Legacy',
            'secret' => null,
            'redirect_uris' => ['https://legacy.example/callback'],
            'grant_types' => ['authorization_code'],
            'revoked' => false,
        ]);
        Log::spy();
        $this->signIn();

        $this->get('/oauth/authorize?'.$this->authorizationQuery('https://legacy.example/app', [
            'redirect_uri' => 'https://legacy.example/callback',
        ]))->assertOk()->assertJsonPath('client.id', 'https://legacy.example/app');

        $this->assertSame(0, $this->requestsSent());
        Log::shouldNotHaveReceived('warning');
    }

    public function testAnAddressThatBelongsToADocumentIdentifiedClientStaysRefusedWhileTheModeIsOff()
    {
        Passport::clientMetadataDocuments();
        $this->publish();
        $this->signIn();
        $this->get('/oauth/authorize?'.$this->authorizationQuery())->assertOk();

        Passport::clientMetadataDocuments(false);
        Log::spy();

        $this->get('/oauth/authorize?'.$this->authorizationQuery())
            ->assertStatus(401)
            ->assertJsonPath('error', 'invalid_client');

        Log::shouldNotHaveReceived('warning');
    }

    public function testTheDeviceAuthorizationEndpointNeverFetchesForADocumentAddress()
    {
        Passport::clientMetadataDocuments();
        $this->publish();

        $this->post('/oauth/device/code', [
            'client_id' => $this->documentUrl,
            'scope' => 'create',
        ])->assertStatus(401);

        $this->assertSame(0, $this->requestsSent());
        $this->assertSame(0, Client::query()->count());
    }

    public function testAnAddressThatADatabaseCannotTellApartFromAnotherIsRefusedAndTheOtherRecordIsLeftAlone()
    {
        // A column that, like MySQL's default, matches addresses regardless of case.
        $this->dropTheColumn();
        DB::statement('alter table oauth_clients add column metadata_document_url varchar(255) collate nocase');
        DB::statement('create unique index oauth_clients_metadata_document_url_unique on oauth_clients (metadata_document_url)');

        $other = Client::query()->forceCreate([
            'name' => 'Victim',
            'secret' => null,
            'redirect_uris' => ['https://victim.example/callback'],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'revoked' => false,
            'metadata_document_url' => 'https://client.example/OAUTH/client.json',
        ]);

        Log::spy();
        Passport::clientMetadataDocuments();
        $this->publish($this->document(['client_name' => 'Attacker']));
        $this->signIn();

        $this->get('/oauth/authorize?'.$this->authorizationQuery())
            ->assertStatus(401)
            ->assertJsonPath('error', 'invalid_client');

        // The refusal is not a failed fetch: the document stays cached and the address is not delayed.
        $key = 'passport:client-metadata:'.hash('sha256', $this->documentUrl);
        $this->assertFalse(Cache::has($key.':delayed'));
        $this->assertNotEmpty(array_filter(
            array_keys((fn () => $this->storage)->call(Cache::getStore())),
            fn (string $name): bool => str_starts_with($name, $key.':document:')
        ));

        $other->refresh();
        $this->assertSame('Victim', $other->name);
        $this->assertSame(['https://victim.example/callback'], $other->redirect_uris);
        $this->assertSame(1, Client::query()->count());
        Log::shouldHaveReceived('warning')->withArgs(
            fn (string $message): bool => str_contains($message, 'differs only in case')
        )->once();
    }

    #[DataProvider('otherResponseTypes')]
    public function testOnlyTheCodeResponseTypeFetchesADocumentOrCreatesARecord(string $responseType)
    {
        Passport::clientMetadataDocuments();
        $this->publish();
        $this->signIn();

        $this->get('/oauth/authorize?'.$this->authorizationQuery(overrides: ['response_type' => $responseType]));

        $this->assertSame(0, $this->requestsSent());
        $this->assertSame(0, Client::query()->count());
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function otherResponseTypes(): array
    {
        return ['implicit' => ['token'], 'an unknown one' => ['nonsense'], 'a hybrid one' => ['code token']];
    }

    /**
     * @return array<string, array{0: array<string, int>}>
     */
    public static function impossibleSettings(): array
    {
        return [
            'a zero connect timeout' => [['connectTimeout' => 0]],
            'a negative timeout' => [['timeout' => -1]],
            'a zero maximum size' => [['maximumSize' => 0]],
            'a negative default lifetime' => [['defaultLifetime' => -60]],
            'a zero minimum lifetime' => [['minimumLifetime' => 0]],
            'a zero maximum lifetime' => [['maximumLifetime' => 0]],
            'a minimum above the maximum' => [['minimumLifetime' => 7200, 'maximumLifetime' => 3600]],
        ];
    }

    /**
     * @param  array<string, int>  $settings
     */
    #[DataProvider('impossibleSettings')]
    public function testImpossibleSettingsAreRefused(array $settings)
    {
        $this->expectException(InvalidArgumentException::class);

        Passport::clientMetadataDocuments(...$settings);
    }

    public function testASettingThatIsMerelyUnusualIsAccepted()
    {
        Passport::clientMetadataDocuments(minimumLifetime: 3600, maximumLifetime: 3600);

        $this->assertTrue(Passport::clientMetadataDocumentsEnabled());
    }
}

class UrlKeyedClient extends Client
{
    public $incrementing = false;

    protected $keyType = 'string';

    /**
     * Get the columns that should receive a unique identifier.
     *
     * @return array<int, string>
     */
    public function uniqueIds(): array
    {
        return [];
    }
}
