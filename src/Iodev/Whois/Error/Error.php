<?php

declare(strict_types=1);

namespace Iodev\Whois\Error;

use \Throwable;

class Error
{
    public function __construct(
        public readonly string $id,
        public readonly string $message,
        public readonly array $details = [],
        public readonly ?Throwable $throwable = null,
    ) {}

    public function toString(): string
    {
        $data = [
            'id' => $this->id,
            'message' => $this->message,
            'throwable' => $this->throwable?->getMessage() ?? '-',
        ];
        $flags = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_LINE_TERMINATORS;

        return json_encode($data, $flags);
    }

    public function toDetailedString(): string
    {
        $data = [
            'id' => $this->id,
            'message' => $this->message,
            'throwable_class' => $this->throwable ? $this->throwable::class : '-',
            'throwable_message' => $this->throwable?->getMessage() ?? '-',
            'details' => $this->details,
        ];
        $flags = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_LINE_TERMINATORS;

        return json_encode($data, $flags);
    }
}
