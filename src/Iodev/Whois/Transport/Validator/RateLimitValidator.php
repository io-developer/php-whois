<?php

declare(strict_types=1);

namespace Iodev\Whois\Transport\Validator;

class RateLimitValidator implements ValidatorInterface
{
    protected array $errorDetails = [];

    public function getErrorDetails(): array
    {
        return $this->errorDetails;
    }

    public function validateOutput(string $output): static
    {
        $this->errorDetails = [];

        if (preg_match('~^WHOIS\s+.*?LIMIT\s+EXCEEDED~ui', $output, $m)) {
            $this->errorDetails[] = sprintf('RateLimitError: %s', $m[0]);
        }

        return $this;
    }
}
