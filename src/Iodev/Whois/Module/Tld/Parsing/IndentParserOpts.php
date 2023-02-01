<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\Parsing;

class IndentParserOpts extends BlockParserOpts
{
    public bool $isAutofix = false;

    public array $secondaryStatesSubsets = [];
}