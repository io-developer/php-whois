<?php

declare(strict_types=1);

namespace Iodev\Whois\Transport;

class RequestTag
{
    public const CANCELLED = 'cancelled';
    public const COMPLETED = 'completed';
    public const ERROR = 'error';
    public const MIDDLEWARE_ERROR = 'middleware_error';
}
