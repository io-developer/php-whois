<?php

declare(strict_types=1);

namespace Iodev\Whois\Punycode;

interface IPunycode
{
    function encode(string $unicode): string;

    function decode(string $ascii): string;
}