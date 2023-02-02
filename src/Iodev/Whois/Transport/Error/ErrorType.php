<?php

declare(strict_types=1);

namespace Iodev\Whois\Transport\Error;

class ErrorType
{
    public const LOADING = 'loading';
    public const REQUEST_MIDDLEWARING = 'request_middlewaring';
    public const RESPONSE_MIDDLEWARING = 'response_middlewaring';
    public const OUTPUT_PROCESSING = 'output_processing';
    public const OUTPUT_VALIDATION = 'output_validation';
}
