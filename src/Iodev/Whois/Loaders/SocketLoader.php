<?php

namespace Iodev\Whois\Loaders;

use Iodev\Whois\AsnResponse;
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
        $text = $this->load($whoisHost, $strict ? "={$domain}\r\n" : "{$domain}\r\n");

        return new Response($domain, $text, $whoisHost);
    }

    /**
     * @param string $whoisHost
     * @param string $asn
     * @return AsnResponse
     * @throws ConnectionException
     */
    public function loadAsnResponse($whoisHost, $asn)
    {
        $text = $this->load($whoisHost, "-i origin $asn\r\n");

        return new AsnResponse($asn, $text, $whoisHost);
    }

    private function load($whoisHost, $command)
    {
        $handle = fsockopen($whoisHost, 43);
        if (!$handle) {
            throw new ConnectionException("Could not open socket on port 43");
        }
        fwrite($handle, $command);
        $text = "";
        while (!feof($handle)) {
            $chunk = fread($handle, 8192);
            $text .= $chunk;
        }
        fclose($handle);
        return $text;
    }
}
