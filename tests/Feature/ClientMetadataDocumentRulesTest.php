<?php

namespace Laravel\Passport\Tests\Feature;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use PHPUnit\Framework\Attributes\DataProvider;
use Workbench\Database\Factories\UserFactory;

class ClientMetadataDocumentRulesTest extends PassportTestCase
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
     * @return array<string, array{0: array<string, mixed>}>
     */
    public static function refusedDocuments(): array
    {
        $url = 'https://client.example/oauth/client.json';

        return [
            'a client_id that differs by case' => [['client_id' => 'https://client.example/oauth/CLIENT.json']],
            'no client_id' => [['client_id' => static::MISSING]],

            'a client_name that is not a string' => [['client_name' => 5]],
            'a client_uri that is not a string' => [['client_uri' => 5]],
            'a logo_uri that is not a string' => [['logo_uri' => true]],
            'a scope that is not a string' => [['scope' => 5]],
            'contacts that are not a list' => [['contacts' => 'a@client.example']],
            'a token_endpoint_auth_method that is a list' => [['token_endpoint_auth_method' => ['none']]],
            'contacts that are not strings' => [['contacts' => [1]]],
            'grant_types that are a string' => [['grant_types' => 'authorization_code']],
            'grant_types that are not strings' => [['grant_types' => [1]]],
            'grant_types that include a boolean' => [['grant_types' => ['authorization_code', true]]],
            'response_types that include a number' => [['response_types' => ['code', 1]]],
            'a tos_uri that is not a string' => [['tos_uri' => 5]],
            'a policy_uri that is not a string' => [['policy_uri' => 5]],
            'a jwks_uri that is not a string' => [['jwks_uri' => 5]],
            'an application_type that is not a string' => [['application_type' => 5]],
            'a software_id that is not a string' => [['software_id' => 5]],
            'a software_version that is not a string' => [['software_version' => 5]],
            'a malformed redirect address' => [['redirect_uris' => ['https://client.example/a b']]],
            'response_types that are a string' => [['response_types' => 'code']],
            'grant_types that are an object' => [['grant_types' => ['a' => 'authorization_code']]],
            'response_types that are an object' => [['response_types' => ['a' => 'code']]],
            'redirect_uris that are a string' => [['redirect_uris' => 'https://client.example/callback']],
            'redirect_uris that are not strings' => [['redirect_uris' => [5]]],
            'redirect_uris that are an object' => [['redirect_uris' => ['a' => 'https://client.example/callback']]],
            'a redirect address that is a list' => [['redirect_uris' => [['https://client.example/callback']]]],

            'no redirect_uris' => [['redirect_uris' => static::MISSING]],
            'empty redirect_uris' => [['redirect_uris' => []]],
            'eleven redirect_uris' => [['redirect_uris' => array_map(fn (int $i) => "https://client.example/cb/$i", range(1, 11))]],
            'a relative redirect address' => [['redirect_uris' => ['/callback']]],
            'a redirect address without a host' => [['redirect_uris' => ['https:///callback']]],
            'a redirect address over 2,048 characters' => [['redirect_uris' => ['https://client.example/'.str_repeat('a', 2026)]]],
            'a redirect address with a fragment' => [['redirect_uris' => ['https://client.example/callback#top']]],
            'a redirect address with user information' => [['redirect_uris' => ['https://user@client.example/callback']]],
            'a redirect address with an empty user' => [['redirect_uris' => ['https://@client.example/callback']]],
            'a plain http redirect address' => [['redirect_uris' => ['http://client.example/callback']]],
            'a redirect address that only starts like localhost' => [['redirect_uris' => ['http://localhost.example/callback']]],
            'a custom scheme redirect address' => [['redirect_uris' => ['myapp://callback']]],
            'a custom scheme on a loopback host' => [['redirect_uris' => ['myapp://localhost/callback']]],
            'one bad redirect address among good ones' => [['redirect_uris' => ['https://client.example/callback', 'myapp://callback']]],

            'supported methods without none' => [['token_endpoint_auth_methods_supported' => ['private_key_jwt']]],
            'a method outside the supported methods' => [[
                'token_endpoint_auth_methods_supported' => ['none'],
                'token_endpoint_auth_method' => 'private_key_jwt',
            ]],
            'empty supported methods' => [['token_endpoint_auth_methods_supported' => []]],
            'null supported methods' => [['token_endpoint_auth_methods_supported' => null]],
            'supported methods that are a string' => [['token_endpoint_auth_methods_supported' => 'none']],
            'supported methods that include a number' => [['token_endpoint_auth_methods_supported' => ['none', 5]]],
            'supported methods that are an object' => [['token_endpoint_auth_methods_supported' => ['a' => 'none']]],
            'client authentication by key' => [['token_endpoint_auth_method' => 'private_key_jwt']],
            'a client_secret' => [['client_secret' => 'shh']],
            'an empty client_secret' => [['client_secret' => null]],
            'a client_secret_expires_at' => [['client_secret_expires_at' => 0]],
            'grant_types without authorization_code' => [['grant_types' => ['implicit', 'refresh_token']]],
            'response_types without code' => [['response_types' => ['token']]],
            'a client_name over 255 characters' => [['client_name' => str_repeat('a', 256)]],
            'a client_uri that is plain http' => [['client_uri' => 'http://client.example/']],
            'an empty client_uri' => [['client_uri' => '']],
            'an empty logo_uri' => [['logo_uri' => '']],
            'an empty token_endpoint_auth_method' => [['token_endpoint_auth_method' => '']],
            'empty grant_types' => [['grant_types' => '']],
            'empty response_types' => [['response_types' => '']],
            'a logo_uri that is a data address' => [['logo_uri' => 'data:image/png;base64,AAAA']],
        ];
    }

    /**
     * @param  array<string, mixed>  $overrides
     */
    #[DataProvider('refusedDocuments')]
    public function testAnUnacceptableDocumentIsRefusedAndNothingIsWritten(array $overrides)
    {
        $this->publish($this->document($overrides));

        $response = $this->authorize();

        $response->assertStatus(401);
        $this->assertSame('invalid_client', $response->json('error'));
        $this->assertSame("The client's metadata document could not be used.", $response->json('error_description'));
        $this->assertSame(0, Client::query()->count());
    }

    public function testAnUnacceptableDocumentDoesNotUpdateTheExistingClient()
    {
        $this->publish();
        $this->authorize()->assertOk();

        $this->travel(11)->minutes();
        $this->publish($this->document([
            'client_name' => 'Renamed',
            'redirect_uris' => ['https://client.example/elsewhere'],
            'client_secret' => 'shh',
        ]));

        $this->authorize()->assertStatus(401);

        $client = Client::query()->sole();
        $this->assertSame('Example Agent', $client->name);
        $this->assertSame(['https://client.example/callback'], $client->redirect_uris);
    }

    public function testTheReasonIsLoggedAtWarningLevel()
    {
        Log::spy();
        $this->publish($this->document(['token_endpoint_auth_method' => 'private_key_jwt']));

        $this->authorize()->assertStatus(401);

        $this->assertRefusalLogged('token endpoint auth method');
    }

    /**
     * @return array<string, array{0: array<string, mixed>, 1: string[]}>
     */
    public static function acceptedDocuments(): array
    {
        return [
            'loopback IPv4' => [['redirect_uris' => ['http://127.0.0.1:33418/']], ['http://127.0.0.1:33418/']],
            'loopback IPv6' => [['redirect_uris' => ['http://[::1]/callback']], ['http://[::1]/callback']],
            'localhost' => [['redirect_uris' => ['http://localhost/callback']], ['http://localhost/callback']],
            'localhost in capitals' => [['redirect_uris' => ['http://LOCALHOST:8080/callback']], ['http://LOCALHOST:8080/callback']],
            'ten redirect addresses' => [
                ['redirect_uris' => $ten = array_map(fn (int $i) => "https://client.example/cb/$i", range(1, 10))],
                $ten,
            ],
            'a redirect address of 2,048 characters' => [
                ['redirect_uris' => [$long = 'https://client.example/'.str_repeat('a', 2025)]],
                [$long],
            ],
            'supported methods with none and the method none' => [
                ['token_endpoint_auth_methods_supported' => ['none'], 'token_endpoint_auth_method' => 'none'],
                ['https://client.example/callback'],
            ],
            'supported methods with none and a key method' => [
                ['token_endpoint_auth_methods_supported' => ['private_key_jwt', 'none']],
                ['https://client.example/callback'],
            ],
            'the supported methods spelled out' => [
                [
                    'token_endpoint_auth_method' => 'none',
                    'grant_types' => ['authorization_code', 'refresh_token'],
                    'response_types' => ['code'],
                    'client_uri' => 'https://client.example/',
                    'logo_uri' => 'https://client.example/logo.png',
                ],
                ['https://client.example/callback'],
            ],
        ];
    }

    /**
     * @param  array<string, mixed>  $overrides
     * @param  string[]  $redirectUris
     */
    #[DataProvider('acceptedDocuments')]
    public function testAnAcceptableDocumentIsStored(array $overrides, array $redirectUris)
    {
        $this->publish($this->document($overrides));

        $this->authorize(null, ['redirect_uri' => $redirectUris[0]])->assertStatus(200);

        $this->assertSame($redirectUris, Client::query()->sole()->redirect_uris);
    }

    public function testTheDocumentOfChatGptIsAccepted()
    {
        $url = 'https://chatgpt.com/oauth/client.json';
        $this->publish([
            'client_id' => $url,
            'client_uri' => 'https://chatgpt.com/',
            'redirect_uris' => ['https://chatgpt.com/connector_platform_oauth_redirect'],
            'token_endpoint_auth_method' => 'private_key_jwt',
            'token_endpoint_auth_methods_supported' => ['none', 'private_key_jwt'],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'client_name' => 'ChatGPT',
            'logo_uri' => 'https://persistent.oaistatic.com/sonic/misc/openai-logo.png',
            'token_endpoint_auth_signing_alg' => 'RS256',
            'jwks_uri' => 'https://chatgpt.com/oauth/jwks.json',
        ], url: $url);

        $this->authorize($url, ['redirect_uri' => 'https://chatgpt.com/connector_platform_oauth_redirect'])
            ->assertOk()
            ->assertJsonPath('client.name', 'ChatGPT');

        $client = Client::query()->sole();
        $this->assertNull($client->secret);
        $this->assertFalse($client->confidential());
    }

    public function testANameOf255CharactersIsAccepted()
    {
        $this->publish($this->document(['client_name' => $name = str_repeat('a', 255)]));

        $this->authorize()->assertOk()->assertJsonPath('client.name', $name);
    }

    public function testWithoutANameTheClientIsNamedAfterTheHost()
    {
        $this->publish($this->document(['client_name' => static::MISSING]));

        $this->authorize()->assertOk()->assertJsonPath('client.name', 'client.example');
        $this->assertSame('client.example', Client::query()->sole()->name);
    }

    public function testTheWebsiteAndTheLogoAreNotStored()
    {
        $this->publish($this->document([
            'client_uri' => 'https://client.example/',
            'logo_uri' => 'https://client.example/logo.png',
        ]));

        $this->authorize()->assertOk();

        $attributes = Client::query()->sole()->getAttributes();

        $this->assertArrayNotHasKey('client_uri', $attributes);
        $this->assertArrayNotHasKey('logo_uri', $attributes);
        $this->assertNotContains('https://client.example/logo.png', array_map('strval', $attributes));
    }
}
