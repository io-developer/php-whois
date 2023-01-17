<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Asn;

class AsnServer
{
    public const DEFAULT_QUERY_FORMAT = "-i origin %s\r\n";

    public function __construct(
        public readonly string $host,
        public readonly AsnParser $parser,
        public readonly string $queryFormat,
    ) {}

    public function buildQuery(string $asn): string
    {
        return sprintf($this->queryFormat, $asn);
    }
}
