<?php

declare(strict_types=1);

namespace Iodev\Whois\Transport\Middleware\Response;

use Iodev\Whois\Transport\Response;
use Iodev\Whois\Transport\ResponseTag;

class RateLimitChecker implements ResponseMiddlewareInterface
{
    public function processResponse(Response $response): void
    {
        $output = $response->getOutput();
        if (empty($output)) {
            return;
        }
        if (preg_match('~^WHOIS\s+.*?LIMIT\s+EXCEEDED~ui', $output, $m)) {
            $response->tagErrorWith(ResponseTag::WHOIS_RATE_LIMIT, 'WHOIS rate limit detected', [
                'matched_text' => $m[0],
            ]);
        }
    }
}
