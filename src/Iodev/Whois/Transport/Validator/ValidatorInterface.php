<?php

declare(strict_types=1);

namespace Iodev\Whois\Transport\Validator;

interface ValidatorInterface
{
    public function getErrorDetails(): array;

    public function validateOutput(string $output): static;
}
