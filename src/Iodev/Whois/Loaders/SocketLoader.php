<?php

namespace Iodev\Whois\Loaders;

use Iodev\Whois\Exceptions\ConnectionException;
use Iodev\Whois\Response;

class SocketLoader implements ILoader
{
    /**
     * @param string $whoisHost
     * @param string $domain
     * @param bool $strict
     * @return Response
     * @throws ConnectionException
     */
    public function loadResponse($whoisHost, $domain, $strict = false)
    {
        $handle = fsockopen($whoisHost, 43);
        if (!$handle) {
            throw new ConnectionException("Could not open socket on port 43");
        }
        fputs($handle, $strict ? "={$domain}\n" : "{$domain}\n");
        $text = "";
        while (!feof($handle)) {
            $chunk = fread($handle, 8192);
            $text .= $chunk;
        }
        fclose($handle);
        return new Response($domain, $text, $whoisHost);
    }
}
