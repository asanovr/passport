<?php

namespace Laravel\Passport\ClientMetadata;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use GuzzleHttp\Psr7\Utils;
use Psr\Http\Message\StreamInterface;

/**
 * A stream that stops accepting bytes at its limit, which aborts the transfer feeding it.
 *
 * @internal
 */
class LimitedStream implements StreamInterface
{
    use StreamDecoratorTrait;

    /**
     * Indicates if more bytes than the limit were offered.
     */
    public bool $exceeded = false;

    protected StreamInterface $stream;

    protected int $written = 0;

    /**
     * Create a new limited stream instance.
     */
    public function __construct(protected int $limit)
    {
        $this->stream = Utils::streamFor(fopen('php://temp', 'w+'));
    }

    /**
     * Write data to the stream, unless the limit would be exceeded.
     */
    public function write(string $string): int
    {
        if ($this->written + strlen($string) > $this->limit) {
            $this->exceeded = true;

            return 0;
        }

        $this->written += strlen($string);

        return $this->stream->write($string);
    }
}
