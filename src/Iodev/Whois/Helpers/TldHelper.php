<?php

namespace Iodev\Whois\Helpers;

use Iodev\Whois\Exceptions\ConnectionException;

class TldHelper
{
    const TLD_LIST_URL = 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt';
    const TLD_WHOIS_HOST_TPL = '%s.whois-servers.net';

    /**
     * @param string|null $url
     * @return string[]
     * @throws ConnectionException
     */
    public static function loadTldList($url = null)
    {
        $url = $url ? $url : self::TLD_LIST_URL;
        $content = file_get_contents($url);
        if ($content === false) {
            throw new ConnectionException("Url cannot be loaded $url");
        }
        $tlds = [];
        foreach (ParserHelper::splitLines($content) as $line) {
            $line = trim($line, ".\t\0\x0B ");
            if ($line && preg_match('~^[-\da-z]+$~ui', $line)) {
                $tlds[] = '.' . mb_strtolower($line);
            }
        }
        return $tlds;
    }

    /**
     * @param string $tld
     * @return string[];
     */
    public static function loadWhoisHosts($tld)
    {
        $infoHost = sprintf(self::TLD_WHOIS_HOST_TPL, trim($tld, ".\t\0\x0B "));
        $hosts = [];
        foreach (dns_get_record($infoHost, DNS_CNAME) as $r) {
            $hosts[] = mb_strtolower($r['target']);
        }
        return $hosts;
    }
}
