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
            Schema::getConnection()->statement(
                'create unique index oauth_clients_metadata_document_url_unique on oauth_clients (metadata_document_url) where metadata_document_url is not null'
            );
        }
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('oauth_clients', function (Blueprint $table) {
            $table->dropUnique(['metadata_document_url']);
            $table->dropColumn('metadata_document_url');
        });
    }

    /**
     * Get the migration connection name.
     */
    public function getConnection(): ?string
    {
        return $this->connection ?? config('passport.connection');
    }
};
