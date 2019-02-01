<?php

namespace Iodev\Whois\Loaders;

use Iodev\Whois\Exceptions\ConnectionException;
use Iodev\Whois\Exceptions\WhoisException;
use Iodev\Whois\Helpers\TextHelper;

class SocketLoader implements ILoader
{
    public function __construct($timeout = 60)
    {
        $this->setTimeout($timeout);
    }

    /** @var int */
    private $timeout;

    /**
     * @return int
     */
    public function getTimeout()
    {
        return $this->timeout;
    }

    /**
     * @param int $seconds
     * @return $this
     */
    public function setTimeout($seconds)
    {
        $this->timeout = max(0, (int)$seconds);
        return $this;
    }

    /**
     * @param string $whoisHost
     * @param string $query
     * @return string
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function loadText($whoisHost, $query)
    {
        if (!gethostbynamel($whoisHost)) {
            throw new ConnectionException("Host is unreachable: $whoisHost");
        }
        $errno = null;
        $errstr = null;
        $handle = @fsockopen($whoisHost, 43, $errno, $errstr, $this->timeout);
        if (!$handle) {
            throw new ConnectionException($errstr, $errno);
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

        return $this->validateResponse(TextHelper::toUtf8($text));
    }

    /**
     * @param string $text
     * @return mixed
     * @throws WhoisException
     */
    private function validateResponse($text)
    {
        if (preg_match('~^WHOIS\s+.*?LIMIT\s+EXCEEDED~ui', $text, $m)) {
            throw new WhoisException($m[0]);
        }
        return $text;
    }
}
