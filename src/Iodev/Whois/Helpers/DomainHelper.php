<?php

declare(strict_types=1);

namespace Iodev\Whois\Helpers;

use Iodev\Whois\Factory;

class DomainHelper
{
    public static function compareNames(string $a, string $b): bool
    {
        $a = self::toAscii($a);
        $b = self::toAscii($b);
        return ($a == $b);
    }
    
    public static function toAscii(string $domain): string
    {
        if (empty($domain) || strlen($domain) >= 255) {
            return '';
        }
        $cor = self::correct($domain);
        return Factory::get()->createPunycode()->encode($cor);
    }
    
    public static function toUnicode(string $domain): string
    {
        if (empty($domain) || strlen($domain) >= 255) {
            return '';
        }
        $cor = self::correct($domain);
        return Factory::get()->createPunycode()->decode($cor);
    }

    public static function filterAscii(string $domain): string
    {
        $domain = self::correct($domain);
        // Pick first part before space
        $domain = explode(" ", $domain)[0];
        // All symbols must be valid
        if (preg_match('~[^-.\da-z]+~ui', $domain)) {
            return "";
        }
        return $domain;
    }

    private static function correct(string $domain): string
    {
        $domain = trim($domain);
        // Fix for .UZ whois response
        while (preg_match('~\bnot\.defined\.?\b~ui', $domain)) {
            $domain = preg_replace('~\bnot\.defined\.?\b~ui', '', $domain);
        }
        return rtrim(preg_replace('~\s*\.\s*~ui', '.', $domain), ".-\t ");
    }
}
