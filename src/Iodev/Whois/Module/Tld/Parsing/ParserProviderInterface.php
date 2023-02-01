<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\Parsing;

interface ParserProviderInterface
{
    public function getByType(string $type): ParserInterface;

    public function getByClassName(string $className, ?string $type = null): ParserInterface;
    
    public function getDefault(): ParserInterface;
}
