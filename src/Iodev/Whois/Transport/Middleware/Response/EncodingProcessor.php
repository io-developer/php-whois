<?php

declare(strict_types=1);

namespace Iodev\Whois\Transport\Middleware\Response;

use Iodev\Whois\Tool\TextTool;
use Iodev\Whois\Transport\Response;
use Iodev\Whois\Transport\ResponseTag;

class EncodingProcessor implements ResponseMiddlewareInterface
{
    public function __construct(
        protected TextTool $textTool
    ) {}

    public function processResponse(Response $response): void
    {
        $src = $response->getOutput();
        if (empty($src)) {
            return;
        }
        $dst = $this->textTool->toUtf8($src);
        if ($src !== $dst) {
            $response->tagWith(ResponseTag::OUTPUT_ENCODING_CHANGED);
        }
        $response->setOutput($dst);
    }
}
