<?php

declare(strict_types=1);

namespace Iodev\Whois\Transport\Middleware\Request;

use Iodev\Whois\Transport\Request;

interface RequestMiddlewareInterface
{
    public function processRequest(Request $request): void;
}
