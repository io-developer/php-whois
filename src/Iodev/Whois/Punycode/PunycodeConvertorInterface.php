<?php

namespace Iodev\Whois\Punycode;

interface PunycodeConvertorInterface
{
    function encode(string $unicode): string;

    function decode(string $ascii): string;
}