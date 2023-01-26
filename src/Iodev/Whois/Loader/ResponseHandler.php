<?php

declare(strict_types=1);

namespace Iodev\Whois\Loader;

use Iodev\Whois\Exception\WhoisException;
use Iodev\Whois\Tool\TextTool;

class ResponseHandler
{
    public function __construct(
        protected TextTool $textTool
    ) {}

    /**
     * @throws WhoisException
     */
    public function handleText(string $text): string
    {
        $handled = $this->textTool->toUtf8($text);
        $this->validateText($handled);

        return $handled;
    }

    /**
     * @throws WhoisException
     */
    public function validateText(string $text): void
    {
        if (preg_match('~^WHOIS\s+.*?LIMIT\s+EXCEEDED~ui', $text, $m)) {
            throw new WhoisException($m[0]);
        }
    }
}
