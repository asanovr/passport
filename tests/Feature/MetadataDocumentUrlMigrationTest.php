<?php

namespace Laravel\Passport\Tests\Feature;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Orchestra\Testbench\Concerns\WithWorkbench;
use Orchestra\Testbench\TestCase;

class MetadataDocumentUrlMigrationTest extends TestCase
{
    use WithWorkbench;

    protected function setUp(): void
    {
        parent::setUp();

        $this->artisan('migrate');
    }

    public function testTheColumnIsRemovedWithItsIndex()
    {
        $this->migration()->down();

        $this->assertFalse(Schema::hasColumn('oauth_clients', 'metadata_document_url'));
        $this->assertEmpty($this->indexesOnTheColumn());

        $this->migration()->up();
    }

    public function testTheColumnIsNullableAndIndexedWithoutBeingUnique()
    {
        $this->migration()->down();
        $this->migration()->up();

        $indexes = $this->indexesOnTheColumn();

        $this->assertCount(1, $indexes);
        $this->assertFalse($indexes[0]['unique']);
        $this->assertSame(['metadata_document_url'], $indexes[0]['columns']);
    }

    public function testManyClientsMayShareAnAddressOrHaveNone()
    {
        foreach (['https://client.example/a', 'https://client.example/a', null, null] as $address) {
            DB::table('oauth_clients')->insert([
                'id' => (string) Str::uuid(),
                'name' => 'Client',
                'redirect_uris' => '[]',
                'grant_types' => '[]',
                'revoked' => false,
                'metadata_document_url' => $address,
            ]);
        }

        $this->assertSame(4, DB::table('oauth_clients')->count());
    }

    /**
     * Get the indexes of the clients table that cover the metadata document URL column.
     *
     * @return list<array<string, mixed>>
     */
    protected function indexesOnTheColumn(): array
    {
        return array_values(array_filter(
            Schema::getIndexes('oauth_clients'),
            fn (array $index): bool => in_array('metadata_document_url', $index['columns'], true),
        ));
    }

    protected function migration(): object
    {
        return require __DIR__.'/../../database/migrations/2026_10_28_000001_add_metadata_document_url_to_oauth_clients_table.php';
    }
}
