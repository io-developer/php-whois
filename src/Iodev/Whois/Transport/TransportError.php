<?php

declare(strict_types=1);

namespace Iodev\Whois\Transport\Error;

use \Throwable;

class TransportError
{
    public function __construct(
        public readonly string $tag,
        public readonly string $message,
        public readonly array $details = [],
        public readonly ?Throwable $throwable = null,
    ) {}

    public function toString(): string
    {
        $data = [
            'tag' => $this->tag,
            'message' => $this->message,
            'throwable' => $this->throwable?->getMessage() ?? '-',
        ];
        $flags = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_LINE_TERMINATORS;

        return json_encode($data, $flags);
    }
}
