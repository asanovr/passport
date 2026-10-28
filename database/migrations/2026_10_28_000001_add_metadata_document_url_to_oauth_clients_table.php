<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        // SQL Server treats every NULL in a unique index as equal, so there the index leaves them out.
        $filtered = Schema::getConnection()->getDriverName() === 'sqlsrv';

        Schema::table('oauth_clients', function (Blueprint $table) use ($filtered) {
            $column = $table->string('metadata_document_url', 255)->nullable()->after('provider');

            if (! $filtered) {
                $column->unique();
            }
        });

        if ($filtered) {
            $connection = Schema::getConnection();

            $connection->statement(sprintf(
                'create unique index %s on %s (metadata_document_url) where metadata_document_url is not null',
                $connection->getSchemaGrammar()->wrap($this->indexName()),
                $connection->getSchemaGrammar()->wrap($connection->getTablePrefix().'oauth_clients'),
            ));
        }
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        $filtered = Schema::getConnection()->getDriverName() === 'sqlsrv';

        Schema::table('oauth_clients', function (Blueprint $table) use ($filtered) {
            $table->dropUnique($filtered ? $this->indexName() : ['metadata_document_url']);
            $table->dropColumn('metadata_document_url');
        });
    }

    /**
     * Get the name of the filtered unique index, as the schema builder names a unique index.
     */
    protected function indexName(): string
    {
        $connection = Schema::getConnection();

        $prefix = $connection->getConfig('prefix_indexes') ? $connection->getConfig('prefix') : '';

        return strtolower($prefix.'oauth_clients_metadata_document_url_unique');
    }

    /**
     * Get the migration connection name.
     */
    public function getConnection(): ?string
    {
        return $this->connection ?? config('passport.connection');
    }
};
