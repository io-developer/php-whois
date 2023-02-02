<?php

declare(strict_types=1);

namespace Iodev\Whois\Transport\Processor;

interface ProcessorInterface
{
    public function processOutput(string $output): string;
}
