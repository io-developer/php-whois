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
    public static function correct($domain)
    {
        // Fix for .UZ whois response
        while (preg_match('~\bnot\.defined\.?\b~ui', $domain)) {
            $domain = preg_replace('~\bnot\.defined\.?\b~ui', '', $domain);
        }
        return mb_strtolower(rtrim(preg_replace('~\s*\.\s*~ui', '.', $domain), ".-\t "));
    }

    /**
     * @param string $domain
     * @param string $zone
     * @return bool
     */
    public static function belongsToZone($domain, $zone)
    {
        $pos = mb_strpos($domain, $zone);
        return ($pos !== false && $pos == (mb_strlen($domain) - mb_strlen($zone)));
    }
}
