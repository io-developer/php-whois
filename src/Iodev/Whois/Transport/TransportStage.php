<?php

declare(strict_types=1);

namespace Iodev\Whois\Transport;

class TransportStage
{
    public const PREPARING = 'preparing';
    public const REQUEST_MIDDLEWARING = 'request_middlewaring';
    public const LOADING = 'loading';
    public const RESPONSE_MIDDLEWARING = 'response_middlewaring';
    public const COMPLETE = 'complete';
}
