<?php

declare(strict_types=1);

namespace Iodev\Whois\Transport;

class RequestState
{
    public const NEW = 'new';
    public const COMPLETED = 'completed';
    public const CANCELLED = 'calcelled';
    public const MIDDLEWARE_ERROR = 'middleware_error';
    public const ERROR = 'error';
}
