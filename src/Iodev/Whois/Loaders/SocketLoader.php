<?php

namespace Iodev\Whois\Loaders;

use Iodev\Whois\Exceptions\ConnectionException;

class SocketLoader implements ILoader
{
    /**
     * @param string $whoisHost
     * @param string $query
     * @return string
     * @throws ConnectionException
     */
    public function loadText($whoisHost, $query)
    {
        $handle = fsockopen($whoisHost, 43);
        if (!$handle) {
            throw new ConnectionException("Socket cannot be open on port 43");
        }
        if (false === fwrite($handle, $query)) {
            throw new ConnectionException("Query cannot be written");
        }
        $text = "";
        while (!feof($handle)) {
            $chunk = fread($handle, 8192);
            if (false === $chunk) {
                throw new ConnectionException("Response chunk cannot be read");
            }
            $text .= $chunk;
        }
        fclose($handle);
        $textUtf8 = iconv('windows-1250', 'utf-8', $text);
        return $textUtf8 ? $textUtf8 : $text;
    }
}
