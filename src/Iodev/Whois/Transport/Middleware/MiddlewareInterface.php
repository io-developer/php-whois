<?php

declare(strict_types=1);

namespace Iodev\Whois\Transport\Middleware;

use Iodev\Whois\Transport\Request;
use Iodev\Whois\Transport\Response;

interface MiddlewareInterface
{
    public function processRequest(Request $request): void;

    public function processResponse(Response $response): void;
}
