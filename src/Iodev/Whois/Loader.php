<?php

namespace Iodev\Whois;

use Iodev\Whois\Exceptions\ConnectionException;

class Loader
{
    /**
     * @param string $whoisHost
     * @param string $domain
     * @param bool $strict
     * @return string
     * @throws ConnectionException
     */
    public function loadText($whoisHost, $domain, $strict = false)
    {
        $handle = fsockopen($whoisHost, 43);
        if (!$handle) {
            throw new ConnectionException("Could not open socket on port 43");
        }
        
        fputs($handle, $strict ? "={$domain}\n" : "{$domain}\n");
        $responseText = "";
        while (!feof($handle)) {
            $responseText .= fgets($handle, 128);
        }
        fclose($handle);
        
        return $responseText;
    }
}
