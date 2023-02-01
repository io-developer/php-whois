<?php

declare(strict_types=1);

namespace Iodev\Whois\Transport\Loader;

use Iodev\Whois\Exception\ConnectionException;
use Iodev\Whois\Exception\WhoisException;

class CurlLoader implements LoaderInterface
{
    protected array $options = [];

    public function __construct(
        protected ResponseHandler $responseHandler,
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
        $this->timeout = max(0, (int)$seconds);
        return $this;
    }

    public function getOptions(): array
    {
        return $this->options;
    }

    public function setOptions(array $opts): static
    {
        $this->options = $opts;
        return $this;
    }

    public function replaceOptions(array $opts): static
    {
        $this->options = array_replace($this->options, $opts);
        return $this;
    }

    /**
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function loadText(string $whoisHost, string $query): string
    {
        if (!gethostbynamel($whoisHost)) {
            throw new ConnectionException("Host is unreachable: $whoisHost");
        }
        $input = fopen('php://temp','r+');
        if (!$input) {
            throw new ConnectionException('Query stream not created');
        }
        fwrite($input, $query);
        rewind($input);

        $curl = curl_init();
        if (!$curl) {
            throw new ConnectionException('Curl not created');
        }
        curl_setopt_array($curl, array_replace($this->options, [
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_PROTOCOLS => CURLPROTO_TELNET,
            CURLOPT_URL => "telnet://$whoisHost:43",
            CURLOPT_INFILE => $input,
        ]));

        $result = curl_exec($curl);
        $errstr = curl_error($curl);
        $errno = curl_errno($curl);
        curl_close($curl);
        fclose($input);

        if ($result === false) {
            throw new ConnectionException($errstr, $errno);
        }

        return $this->responseHandler->handleText($result);
    }
}
