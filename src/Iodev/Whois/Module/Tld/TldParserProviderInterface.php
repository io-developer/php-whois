<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld;

interface TldParserProviderInterface
{
    public function getByType(string $type): TldParser;

    public function getByClassName(string $className, ?string $type = null): TldParser;
    
    public function getDefault(): TldParser;
}
