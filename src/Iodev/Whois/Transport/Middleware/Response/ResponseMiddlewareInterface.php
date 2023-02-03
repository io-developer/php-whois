<?php

declare(strict_types=1);

namespace Iodev\Whois\Transport\Middleware\Response;

use Iodev\Whois\Transport\Response;

interface ResponseMiddlewareInterface
{
    public function processResponse(Response $response): void;
}
