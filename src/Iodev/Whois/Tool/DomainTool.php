<?php

declare(strict_types=1);

namespace Iodev\Whois\Tool;

use Iodev\Whois\Punycode\IPunycode;

class DomainTool
{
    public function __construct(
        protected IPunycode $punycode,
    ) {}

    public function isEqual(string $a, string $b): bool
    {
        $a = $this->toAscii($a);
        $b = $this->toAscii($b);
        return $a === $b;
    }
    
    public function toAscii(string $domain): string
    {
        if (empty($domain) || strlen($domain) >= 255) {
            return '';
        }
        $cor = $this->correct($domain);
        return $this->punycode->encode($cor);
    }
    
    public function toUnicode(string $domain): string
    {
        if (empty($domain) || strlen($domain) >= 255) {
            return '';
        }
        $cor = $this->correct($domain);
        return $this->punycode->decode($cor);
    }

    public function filterAscii(string $domain): string
    {
        $domain = $this->correct($domain);
        // Pick first part before space
        $domain = explode(' ', $domain)[0];
        // All symbols must be valid
        if (preg_match('~[^-.\da-z]+~ui', $domain)) {
            return '';
        }
        return $domain;
    }

    public function correct(string $domain): string
    {
        $domain = trim($domain);
        // Fix for .UZ whois response
        while (preg_match('~\bnot\.defined\.?\b~ui', $domain)) {
            $domain = preg_replace('~\bnot\.defined\.?\b~ui', '', $domain);
        }
        return rtrim(preg_replace('~\s*\.\s*~ui', '.', $domain), ".-\t ");
    }
}
