<?php

namespace Iodev\Whois\Punycode;

use Symfony\Polyfill\Intl\Idn\Idn;

class SymfonyPunycodeCovertor implements PunycodeConvertorInterface
{
    public function encode(string $unicode): string
    {
        return empty($unicode) ? '' : Idn::idn_to_utf8($unicode);
    }

    public function decode(string $ascii): string
    {
        return empty($ascii) ? '' : Idn::idn_to_ascii($ascii);
    }
}
