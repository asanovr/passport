<?php

namespace Laravel\Passport\Tests\Feature;

use Illuminate\Contracts\Cache\Store;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Sleep;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use PHPUnit\Framework\Attributes\DataProvider;

class ClientMetadataDocumentCacheTest extends PassportTestCase
{
    use InteractsWithClientMetadataDocuments;

    protected Carbon $start;

    protected function setUp(): void
    {
        parent::setUp();

        Passport::tokensCan(['create' => 'Create', 'read' => 'Read']);
        Passport::authorizationView(fn ($params) => $params);
        Passport::clientMetadataDocuments();

        Http::preventStrayRequests();

        $this->signIn();
        $this->start = Carbon::now()->startOfSecond();
        $this->travelTo($this->start);
    }

    protected function authorize()
    {
        return $this->get('/oauth/authorize?'.$this->authorizationQuery());
    }

    protected function at(int $seconds): void
    {
        $this->travelTo($this->start->copy()->addSeconds($seconds));
    }

    public function testADocumentIsNotFetchedAgainWhileItIsFresh()
    {
        $this->publish(headers: ['Content-Type' => 'application/json', 'Cache-Control' => 'public, max-age=300']);

        $this->authorize()->assertOk();
        $this->at(299);
        $this->authorize()->assertOk();

        $this->assertSame(1, $this->requestsSent());
    }

    public function testAStaleDocumentIsFetchedAgainAndAChangedOneUpdatesTheClient()
    {
        $this->publish(headers: ['Content-Type' => 'application/json', 'Cache-Control' => 'max-age=300']);
        $this->authorize()->assertOk();

        $this->publish(
            $this->document(['client_name' => 'Renamed', 'redirect_uris' => ['https://client.example/callback']]),
            headers: ['Content-Type' => 'application/json', 'Cache-Control' => 'max-age=300']
        );

        $this->at(299);
        $this->authorize()->assertOk()->assertJsonPath('client.name', 'Example Agent');

        $this->at(301);
        $this->authorize()->assertOk()->assertJsonPath('client.name', 'Renamed');

        $this->assertSame(2, $this->requestsSent());
        $this->assertSame(1, Client::query()->count());
    }

    /**
     * @return array<string, array{0: array<string, string>, 1: int}>
     */
    public static function lifetimes(): array
    {
        $expires = fn (int $seconds) => "expires in $seconds seconds";

        return [
            'max-age' => [['Cache-Control' => 'public, max-age=300'], 300],
            'max-age below the minimum' => [['Cache-Control' => 'max-age=5'], 60],
            'max-age above the maximum' => [['Cache-Control' => 'max-age=999999'], 86400],
            'no-store' => [['Cache-Control' => 'no-store'], 60],
            'no-cache' => [['Cache-Control' => 'no-cache'], 60],
            'no-store, no-cache and max-age=0' => [['Cache-Control' => 'no-store, no-cache, max-age=0'], 60],
            'no-store beats max-age' => [['Cache-Control' => 'max-age=300, no-store'], 60],
            'no header' => [[], 600],
            'Expires without max-age' => [['Expires' => $expires(300)], 300],
            'max-age beats Expires' => [['Cache-Control' => 'max-age=120', 'Expires' => $expires(900)], 120],
            'Expires in the past' => [['Expires' => $expires(-3600)], 60],
            'an invalid Expires' => [['Expires' => '0'], 60],
            'max-age less the Age' => [['Cache-Control' => 'max-age=300', 'Age' => '100'], 200],
            'an Age beyond max-age' => [['Cache-Control' => 'max-age=300', 'Age' => '400'], 60],
            'an invalid Age' => [['Cache-Control' => 'max-age=300', 'Age' => 'soon'], 300],
            'a max-age that is not a number' => [['Cache-Control' => 'max-age=soon'], 60],
            'a negative max-age' => [['Cache-Control' => 'max-age=-5'], 60],
            'an empty max-age' => [['Cache-Control' => 'public, max-age='], 60],
            'an invalid max-age beats Expires' => [['Cache-Control' => 'max-age=soon', 'Expires' => $expires(900)], 60],
        ];
    }

    /**
     * @param  array<string, string>  $headers
     */
    #[DataProvider('lifetimes')]
    public function testTheLifetimeFollowsTheCachingHeadersWithinTheBounds(array $headers, int $lifetime)
    {
        if (isset($headers['Expires'])) {
            $headers['Expires'] = preg_match('/^expires in (-?\d+) seconds$/', $headers['Expires'], $matches) === 1
                ? gmdate('D, d M Y H:i:s \G\M\T', $this->start->getTimestamp() + (int) $matches[1])
                : $headers['Expires'];
        }

        $this->publish(headers: ['Content-Type' => 'application/json'] + $headers);

        $this->authorize()->assertOk();
        $this->at($lifetime - 1);
        $this->authorize()->assertOk();
        $this->assertSame(1, $this->requestsSent());

        $this->at($lifetime + 1);
        $this->authorize()->assertOk();
        $this->assertSame(2, $this->requestsSent());
    }

    public function testExpiresIsMeasuredAgainstTheDateOfTheResponse()
    {
        // A response that was generated 1000 seconds before it was sent, as one that comes from a
        // cache, or from a server whose clock is behind, is.
        $date = $this->start->getTimestamp() - 1000;

        $this->publish(headers: [
            'Content-Type' => 'application/json',
            'Date' => gmdate('D, d M Y H:i:s \G\M\T', $date),
            'Expires' => gmdate('D, d M Y H:i:s \G\M\T', $date + 300),
        ]);

        $this->authorize()->assertOk();
        $this->at(299);
        $this->authorize()->assertOk();
        $this->assertSame(1, $this->requestsSent());

        $this->at(301);
        $this->authorize()->assertOk();
        $this->assertSame(2, $this->requestsSent());
    }

    public function testTheBoundsAndTheDefaultAreSettings()
    {
        Passport::clientMetadataDocuments(defaultLifetime: 120, minimumLifetime: 10, maximumLifetime: 200);

        $this->publish();
        $this->authorize()->assertOk();
        $this->at(119);
        $this->authorize()->assertOk();
        $this->at(121);
        $this->authorize()->assertOk();
        $this->assertSame(2, $this->requestsSent());

        $this->publish(headers: ['Content-Type' => 'application/json', 'Cache-Control' => 'max-age=5']);
        $this->at(121 + 120);
        $this->authorize()->assertOk();
        $this->assertSame(3, $this->requestsSent());
        $this->at(121 + 120 + 9);
        $this->authorize()->assertOk();
        $this->assertSame(3, $this->requestsSent());
        $this->at(121 + 120 + 11);
        $this->authorize()->assertOk();
        $this->assertSame(4, $this->requestsSent());

        $this->publish(headers: ['Content-Type' => 'application/json', 'Cache-Control' => 'max-age=99999']);
        $this->at(1000);
        $this->authorize()->assertOk();
        $this->at(1000 + 199);
        $this->authorize()->assertOk();
        $this->assertSame(5, $this->requestsSent());
        $this->at(1000 + 201);
        $this->authorize()->assertOk();
        $this->assertSame(6, $this->requestsSent());
    }

    public function testAFailedFetchIsNotCachedAndTheFixedDocumentIsFetchedAfterTheDelay()
    {
        $this->publish('Oops', 500);
        $this->authorize()->assertStatus(401);

        $this->publish();
        $this->at(29);
        $this->authorize()->assertStatus(401);
        $this->assertSame(1, $this->requestsSent());

        $this->at(31);
        $this->authorize()->assertOk();
        $this->assertSame(2, $this->requestsSent());
    }

    public function testAnInvalidDocumentIsNotCachedEither()
    {
        $this->publish($this->document(['client_secret' => 'shh']));
        $this->authorize()->assertStatus(401);

        $this->publish();
        $this->at(31);
        $this->authorize()->assertOk();
        $this->assertSame(2, $this->requestsSent());
        $this->assertSame(1, Client::query()->count());
    }

    public function testTheDelayDoublesWithEachFailureUpToTenMinutesAndASuccessResetsIt()
    {
        $this->publish('Oops', 500);
        $now = 0;
        $sent = 0;

        foreach ([30, 60, 120, 240, 480, 600, 600] as $delay) {
            $this->at($now);
            $this->authorize()->assertStatus(401);
            $this->assertSame(++$sent, $this->requestsSent());

            $this->at($now + $delay - 1);
            $this->authorize()->assertStatus(401);
            $this->assertSame($sent, $this->requestsSent());

            $now += $delay + 1;
        }

        $this->publish(headers: ['Content-Type' => 'application/json', 'Cache-Control' => 'max-age=1']);
        $this->at($now);
        $this->authorize()->assertOk();
        $this->assertSame(++$sent, $this->requestsSent());

        // A success resets the delay: the next failure is delayed by 30 seconds again.
        $this->publish('Oops', 500);
        $now += 61;
        $this->at($now);
        $this->authorize()->assertStatus(401);
        $this->assertSame(++$sent, $this->requestsSent());

        $this->at($now + 29);
        $this->authorize()->assertStatus(401);
        $this->assertSame($sent, $this->requestsSent());

        $this->at($now + 31);
        $this->authorize()->assertStatus(401);
        $this->assertSame(++$sent, $this->requestsSent());
    }

    public function testAFailedRefetchIsRefusedEvenWhenTheClientExistsAndExistingTokensStillRefresh()
    {
        $this->publish();
        $tokens = $this->connect();

        $this->publish('Oops', 500);
        $this->at(601);

        $this->authorize()->assertStatus(401)->assertJsonPath('error', 'invalid_client');
        $this->assertSame(2, $this->requestsSent());

        $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $this->documentUrl,
            'refresh_token' => $tokens['refresh_token'],
            'scope' => 'create read',
        ])->assertOk();

        $this->assertSame(2, $this->requestsSent());
    }

    public function testTheTokenEndpointNeverFetches()
    {
        $this->publish();
        $tokens = $this->connect();
        $this->assertSame(1, $this->requestsSent());

        // Fresh.
        $refreshed = $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $this->documentUrl,
            'refresh_token' => $tokens['refresh_token'],
        ])->assertOk()->json();

        // Stale.
        $this->at(86400 * 2);
        $refreshed = $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $this->documentUrl,
            'refresh_token' => $refreshed['refresh_token'],
        ])->assertOk()->json();

        // Missing.
        Cache::flush();
        $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $this->documentUrl,
            'refresh_token' => $refreshed['refresh_token'],
        ])->assertOk();

        $this->assertSame(1, $this->requestsSent());
    }

    public function testAnotherAuthorizationDoesNotStartASecondFetchAndIsRefusedAfterABoundedWait()
    {
        $this->publish();
        Sleep::fake();
        Sleep::syncWithCarbon();

        // The lock that the fetch of this address takes (see the handoff).
        $lock = Cache::lock('passport:client-metadata:'.hash('sha256', $this->documentUrl).':lock', 60);
        $this->assertTrue($lock->get());

        $this->authorize()->assertStatus(401)->assertJsonPath('error', 'invalid_client');

        $this->assertSame(0, $this->requestsSent());
        $this->assertSame(0, Client::query()->count());

        $lock->release();
        $this->at(31);
        $this->authorize()->assertOk();
    }

    public function testAnotherAuthorizationWaitsAtLeastAsLongAsTheFetchItWaitsForMayTake()
    {
        $this->publish();
        Sleep::fake();
        Sleep::syncWithCarbon();

        $lock = Cache::lock('passport:client-metadata:'.hash('sha256', $this->documentUrl).':lock', 60);
        $this->assertTrue($lock->get());

        $this->authorize()->assertStatus(401)->assertJsonPath('error', 'invalid_client');

        // The connect timeout, the timeout and a second more: the holder may spend that long on the fetch.
        $this->assertGreaterThanOrEqual(6, $this->start->diffInSeconds(Carbon::now()));
    }

    public function testADocumentIsFetchedWithoutALockOnACacheStoreThatHasNone()
    {
        Cache::extend('plain', fn () => Cache::repository(new CacheStoreWithoutLocks));
        config(['cache.stores.plain' => ['driver' => 'plain'], 'cache.default' => 'plain']);
        $this->publish();

        $this->authorize()->assertOk();
        $this->authorize()->assertOk();

        $this->assertSame(1, $this->requestsSent());
        $this->assertSame(1, Client::query()->count());
    }

    public function testAFreshDocumentIsUsedWithoutWaitingForALockedFetch()
    {
        $this->publish();
        $this->authorize()->assertOk();

        Sleep::fake();
        Sleep::syncWithCarbon();
        $lock = Cache::lock('passport:client-metadata:'.hash('sha256', $this->documentUrl).':lock', 60);
        $this->assertTrue($lock->get());

        $this->authorize()->assertOk();

        Sleep::assertNeverSlept();
        $this->assertSame(1, $this->requestsSent());
    }

    public function testADelayedAddressIsRefusedWithoutWaitingForALockedFetch()
    {
        $this->publish('Oops', 500);
        $this->authorize()->assertStatus(401);

        Sleep::fake();
        Sleep::syncWithCarbon();
        $lock = Cache::lock('passport:client-metadata:'.hash('sha256', $this->documentUrl).':lock', 60);
        $this->assertTrue($lock->get());

        $this->authorize()->assertStatus(401);

        Sleep::assertNeverSlept();
        $this->assertSame(1, $this->requestsSent());
    }

    public function testAnotherAuthorizationDoesNotFetchAfterTheFetchItWaitedForFailed()
    {
        $this->publish('Oops', 500);
        Sleep::fake();
        Sleep::syncWithCarbon();

        $lock = Cache::lock('passport:client-metadata:'.hash('sha256', $this->documentUrl).':lock', 60);
        $this->assertTrue($lock->get());

        $finished = false;
        Sleep::whenFakingSleep(function () use ($lock, &$finished) {
            if ($finished) {
                return;
            }

            $finished = true;
            $lock->release();

            $this->get('/oauth/authorize?'.$this->authorizationQuery())->assertStatus(401);
        });

        $this->authorize()->assertStatus(401);

        $this->assertTrue($finished);
        $this->assertSame(1, $this->requestsSent());
    }

    public function testAnotherAuthorizationUsesTheResultOfTheFetchItWaitedFor()
    {
        $this->publish();
        Sleep::fake();
        Sleep::syncWithCarbon();

        $lock = Cache::lock('passport:client-metadata:'.hash('sha256', $this->documentUrl).':lock', 60);
        $this->assertTrue($lock->get());

        // While the second request waits, the first one finishes: it fetches the document and releases the lock.
        $finished = false;
        Sleep::whenFakingSleep(function () use ($lock, &$finished) {
            if ($finished) {
                return;
            }

            $finished = true;
            $lock->release();

            $this->get('/oauth/authorize?'.$this->authorizationQuery())->assertOk();
        });

        $this->authorize()->assertOk();

        $this->assertTrue($finished);
        $this->assertSame(1, $this->requestsSent());
        $this->assertSame(1, Client::query()->count());
    }

    public function testSwitchingTheModeOffStopsNewAuthorizationsAndKeepsExistingConnectionsRefreshing()
    {
        $this->publish();
        $tokens = $this->connect();
        $this->assertSame(1, $this->requestsSent());

        Passport::clientMetadataDocuments(false);
        $this->assertFalse(Passport::clientMetadataDocumentsEnabled());

        // The existing client may not authorize again, and nothing is fetched to find out.
        $this->at(86400 * 2);
        $this->authorize()->assertStatus(401)->assertJsonPath('error', 'invalid_client');

        // A new address is unknown.
        $other = 'https://other.example/oauth/client.json';
        $this->publish(url: $other);
        $this->get('/oauth/authorize?'.$this->authorizationQuery($other))->assertStatus(401);

        // Its connections keep working.
        $refreshed = $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $this->documentUrl,
            'refresh_token' => $tokens['refresh_token'],
        ])->assertOk()->json();

        Route::get('/foo', fn () => 'ok')->middleware('auth:api');
        $this->withToken($refreshed['access_token'])->get('/foo')->assertOk();

        $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $other,
            'refresh_token' => $refreshed['refresh_token'],
        ])->assertStatus(401)->assertJsonPath('error', 'invalid_client');

        $this->assertSame(1, $this->requestsSent());
        $this->assertSame(1, Client::query()->count());
    }

    public function testACodeIssuedBeforeTheModeWasSwitchedOffCanStillBeExchanged()
    {
        $this->publish();
        $response = $this->authorize()->assertOk();
        $approved = $this->post('/oauth/authorize', ['auth_token' => $response->json('authToken')]);
        parse_str(parse_url($approved->headers->get('Location'), PHP_URL_QUERY), $params);

        Passport::clientMetadataDocuments(false);

        $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->documentUrl,
            'redirect_uri' => 'https://client.example/callback',
            'code' => $params['code'],
            'code_verifier' => $this->codeVerifier,
        ])->assertOk();

        $this->assertSame(1, $this->requestsSent());
    }

    public function testALoopbackRedirectOfACachedDocumentIsRefusedOnceLoopbackRedirectsAreNotAllowed()
    {
        $this->publish($this->document(['redirect_uris' => ['https://client.example/callback', 'http://127.0.0.1/callback']]));
        $this->authorize()->assertOk();

        Passport::clientMetadataDocuments(allowLoopbackRedirects: false);

        $this->authorize()->assertStatus(401)->assertJsonPath('error', 'invalid_client');
    }

    public function testACacheEntryOfAnotherShapeIsAMissAndTheKeyCarriesAFormatVersion()
    {
        $this->publish();
        $this->authorize()->assertOk();

        $keys = array_filter(
            array_keys((fn () => $this->storage)->call(Cache::getStore())),
            fn (string $key): bool => str_contains($key, ':document:')
        );

        $this->assertNotEmpty($keys);

        foreach ($keys as $key) {
            $this->assertMatchesRegularExpression('/:document:v\d+:/', $key);
            Cache::put($key, ['url' => $this->documentUrl, 'surprise' => true], 600);
        }

        $this->authorize()->assertOk();

        $this->assertSame(2, $this->requestsSent());
    }
}

class CacheStoreWithoutLocks implements Store
{
    /**
     * The values of the store.
     *
     * @var array<string, array{0: mixed, 1: int}>
     */
    protected array $values = [];

    public function get($key)
    {
        if (! isset($this->values[$key]) || $this->values[$key][1] < Carbon::now()->getTimestamp()) {
            return null;
        }

        return $this->values[$key][0];
    }

    public function many(array $keys)
    {
        return array_combine($keys, array_map(fn (string $key) => $this->get($key), $keys));
    }

    public function put($key, $value, $seconds)
    {
        $this->values[$key] = [$value, Carbon::now()->getTimestamp() + $seconds];

        return true;
    }

    public function putMany(array $values, $seconds)
    {
        foreach ($values as $key => $value) {
            $this->put($key, $value, $seconds);
        }

        return true;
    }

    public function increment($key, $value = 1)
    {
        return $this->values[$key][0] = ($this->get($key) ?? 0) + $value;
    }

    public function decrement($key, $value = 1)
    {
        return $this->increment($key, -$value);
    }

    public function forever($key, $value)
    {
        return $this->put($key, $value, 315360000);
    }

    public function touch($key, $seconds)
    {
        return false;
    }

    public function forget($key)
    {
        unset($this->values[$key]);

        return true;
    }

    public function flush()
    {
        $this->values = [];

        return true;
    }

    public function getPrefix()
    {
        return '';
    }
}
