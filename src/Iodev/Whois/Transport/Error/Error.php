<?php

declare(strict_types=1);

namespace Iodev\Whois\Transport\Error;

use \Throwable;

class Error
{
    public function __construct(
        public readonly string $type,
        public readonly string $source,
        public readonly string $message,
        public readonly array $details = [],
        public readonly ?Throwable $throwable = null,
    ) {}

    public function getSummaryMessage(): string
    {
        $data = [
            'type' => $this->type,
            'source' => $this->source,
            'message' => $this->message,
            'details' => $this->details,
            'throwableMessage' => $this->throwable?->getMessage() ?? '',
        ];
        $flags = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_LINE_TERMINATORS;

        return json_encode($data, $flags);
    }
}
