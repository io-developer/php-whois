<?php

declare(strict_types=1);

namespace Iodev\Whois\Tool;

interface PunycodeToolInterface
{
    function encode(string $unicode): string;

    function decode(string $ascii): string;
}