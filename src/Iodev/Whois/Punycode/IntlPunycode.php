<?php

declare(strict_types=1);

namespace Iodev\Whois\Punycode;

class IntlPunycode implements IPunycode
{
    public function encode(string $unicode): string
    {
        if (empty($unicode)) {
            return '';
        }
        $result = defined('INTL_IDNA_VARIANT_UTS46')
            ? idn_to_ascii($unicode, 0, INTL_IDNA_VARIANT_UTS46)
            : idn_to_ascii($unicode);
        return $result ?: '';
    }

    public function decode(string $ascii): string
    {
        if (empty($ascii)) {
            return '';
        }
        $result = defined('INTL_IDNA_VARIANT_UTS46')
            ? idn_to_utf8($ascii, 0, INTL_IDNA_VARIANT_UTS46)
            : idn_to_utf8($ascii);
        return $result ?: '';
    }
}
