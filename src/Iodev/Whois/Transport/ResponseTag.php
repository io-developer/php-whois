<?php

declare(strict_types=1);

namespace Iodev\Whois\Transport;

class ResponseTag
{
    public const REQUEST_HAS_INVALID_STATE = 'request_has_invalid_state';
    public const REQUEST_NOT_SENT = 'request_not_sent';
    public const REQUEST_MIDDLEWARE_ERROR = 'request_middleware_error';
    public const RESPONSE_MIDDLEWARE_ERROR = 'response_middleware_error';
    public const WHOIS_TIMEOUT = 'whois_timeout';
    public const WHOIS_RATE_LIMIT = 'whois_rate_limit';
    public const WHOIS_NO_MATCH = 'whois_no_match';
    public const OUTPUT_ENCODING_CHANGED = 'output_encoding_changed';
}
