<?php

namespace Iodev\Whois\Helpers;

class DomainHelper
{
    /**
     * @param string $a
     * @param string $b
     * @return string
     */
    public static function compareNames($a, $b)
    {
        $a = self::toAscii($a);
        $b = self::toAscii($b);
        return ($a == $b);
    }
    
    /**
     * @param string $domain
     * @return string
     */
    public static function toAscii($domain)
    {
        if (empty($domain)) {
            return "";
        }
        $cor = self::correct($domain);
        if (function_exists("idn_to_ascii")) {
            return defined('INTL_IDNA_VARIANT_UTS46')
                ? idn_to_ascii($cor, 0, INTL_IDNA_VARIANT_UTS46)
                : idn_to_ascii($cor);
        }
        return $cor;
    }
    
    /**
     * @param string $domain
     * @return string
     */
    public static function toUnicode($domain)
    {
        if (empty($domain)) {
            return "";
        }
        $cor = self::correct($domain);
        if (function_exists("idn_to_utf8")) {
            return defined('INTL_IDNA_VARIANT_UTS46')
                ? idn_to_utf8($cor, 0, INTL_IDNA_VARIANT_UTS46)
                : idn_to_utf8($cor);
        }
        return $cor;
    }
    
    /**
     * @param string $domain
     * @return string
     */
    private static function correct($domain)
    {
        // Remove "[description or ip]"
        $domain = trim(preg_replace('~\[.*?\]~ui', '', $domain));
        // Fix for .UZ whois response
        while (preg_match('~\bnot\.defined\.?\b~ui', $domain)) {
            $domain = preg_replace('~\bnot\.defined\.?\b~ui', '', $domain);
        }
        return rtrim(preg_replace('~\s*\.\s*~ui', '.', $domain), ".-\t ");
    }
}
