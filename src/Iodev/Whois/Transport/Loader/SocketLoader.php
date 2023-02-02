<?php

declare(strict_types=1);

namespace Iodev\Whois\Transport\Loader;

use Iodev\Whois\Exception\ConnectionException;
use Iodev\Whois\Exception\WhoisException;

class SocketLoader implements LoaderInterface
{
    protected bool $origEnv = false;

    public function __construct(
        protected int $timeout = 60,
    ) {
        $this->setTimeout($timeout);
    }

    public function getTimeout(): int
    {
        return $this->timeout;
    }

    public function setTimeout(int $seconds): static
    {
        $this->timeout = max(0, $seconds);
        return $this;
    }

    /**
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function loadText(string $whoisHost, string $query): string
    {
        $this->setupEnv();
        if (!gethostbynamel($whoisHost)) {
            $this->teardownEnv();
            throw new ConnectionException("Host is unreachable: $whoisHost");
        }
        $this->teardownEnv();
        $errno = null;
        $errstr = null;
        $handle = @fsockopen($whoisHost, 43, $errno, $errstr, $this->timeout);
        if (!$handle) {
            throw new ConnectionException($errstr, $errno);
        }

        stream_set_timeout($handle, $this->timeout);

        if (false === fwrite($handle, $query)) {
            throw new ConnectionException("Query cannot be written");
        }
        $text = "";
        while (!feof($handle)) {
            $chunk = fread($handle, 8192);
            if (false === $chunk || stream_get_meta_data($handle)['timed_out']) {
                throw new ConnectionException("Response chunk cannot be read");
            }
            $text .= $chunk;
        }
        fclose($handle);

        return $text;
    }

    protected function setupEnv(): void
    {
        $this->origEnv = getenv('RES_OPTIONS');
        putenv("RES_OPTIONS=retrans:1 retry:1 timeout:{$this->timeout} attempts:1");
    }

    protected function teardownEnv(): void
    {
        $this->origEnv === false
            ? putenv("RES_OPTIONS")
            : putenv("RES_OPTIONS={$this->origEnv}")
        ;
    }
}
