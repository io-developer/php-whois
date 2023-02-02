<?php

declare(strict_types=1);

namespace Iodev\Whois\Transport\Processor;

use Iodev\Whois\Tool\TextTool;

class EncodingProcessor implements ProcessorInterface
{
    public function __construct(
        protected TextTool $textTool
    ) {}

    public function processOutput(string $output): string
    {
        return $this->textTool->toUtf8($output);
    }
}
