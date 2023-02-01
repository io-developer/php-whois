<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\Parsing;

use Iodev\Whois\Module\Tld\Dto\LookupInfo;
use Iodev\Whois\Module\Tld\Dto\LookupResponse;

abstract class ParserInterface
{
    public const AUTO = 'auto';
    public const COMMON = 'common';
    public const COMMON_FLAT = 'commonFlat';
    public const BLOCK = 'block';
    public const INDENT = 'indent';
    public const INDENT_AUTOFIX = 'indentAutofix';

    protected array $options = [];

    public function getOptions(): array
    {
        return $this->options;
    }

    public function getOption(string $key, mixed $def = null): mixed
    {
        return array_key_exists($key, $this->options) ? $this->options[$key] : $def;
    }

    public function setOptions(array $options): static
    {
        $this->options = is_array($options) ? $options : [];
        return $this;
    }

    abstract public function getType(): string;

    abstract public function setConfig(array $cfg): static;

    abstract public function parseResponse(LookupResponse $response): ?LookupInfo;
}
