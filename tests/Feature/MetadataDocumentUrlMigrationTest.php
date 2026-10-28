<?php

namespace Laravel\Passport\Tests\Feature;

use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\Concerns\WithWorkbench;
use Orchestra\Testbench\TestCase;

class MetadataDocumentUrlMigrationTest extends TestCase
{
    use WithWorkbench;

    public function testTheSqlServerIndexIsCreatedAndDroppedOnTheSamePrefixedNames()
    {
        $statements = $this->statements(prefix: 'pp_', prefixIndexes: true);

        $this->assertContains(
            'create unique index "pp_oauth_clients_metadata_document_url_unique" on "pp_oauth_clients" (metadata_document_url) where metadata_document_url is not null',
            $statements,
        );
        $this->assertContains(
            'drop index "pp_oauth_clients_metadata_document_url_unique" on "pp_oauth_clients"',
            $statements,
        );
    }

    public function testTheSqlServerIndexNameIsNotPrefixedWhenIndexesAreNotPrefixed()
    {
        $statements = $this->statements(prefix: 'pp_', prefixIndexes: false);

        $this->assertContains(
            'create unique index "oauth_clients_metadata_document_url_unique" on "pp_oauth_clients" (metadata_document_url) where metadata_document_url is not null',
            $statements,
        );
        $this->assertContains(
            'drop index "oauth_clients_metadata_document_url_unique" on "pp_oauth_clients"',
            $statements,
        );
    }

    public function testTheSqlServerIndexNamesAreBareWithoutAPrefix()
    {
        $statements = $this->statements(prefix: '', prefixIndexes: false);

        $this->assertContains(
            'create unique index "oauth_clients_metadata_document_url_unique" on "oauth_clients" (metadata_document_url) where metadata_document_url is not null',
            $statements,
        );
        $this->assertContains(
            'drop index "oauth_clients_metadata_document_url_unique" on "oauth_clients"',
            $statements,
        );
    }

    /**
     * Get the statements the migration runs, up and down, on a SQL Server connection that is not connected.
     *
     * @return list<string>
     */
    protected function statements(string $prefix, bool $prefixIndexes): array
    {
        config([
            'database.connections.mssql' => [
                'driver' => 'sqlsrv',
                'host' => 'localhost',
                'database' => 'passport',
                'username' => 'passport',
                'password' => 'secret',
                'prefix' => $prefix,
                'prefix_indexes' => $prefixIndexes,
            ],
            'database.default' => 'mssql',
        ]);

        DB::purge('mssql');

        $migration = require __DIR__.'/../../database/migrations/2026_10_28_000001_add_metadata_document_url_to_oauth_clients_table.php';

        $log = DB::connection('mssql')->pretend(function () use ($migration) {
            $migration->up();
            $migration->down();
        });

        return array_column($log, 'query');
    }
}
