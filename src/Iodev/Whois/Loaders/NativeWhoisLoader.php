<?php declare(strict_types=1);

namespace Iodev\Whois\Loaders;

use Iodev\Whois\Helpers\TextHelper;
use Iodev\Whois\Exceptions\WhoisException;
use Iodev\Whois\Exceptions\ConnectionException;
use Symfony\Component\Process\Process;

class NativeWhoisLoader implements ILoader
{

    /** @var string */
    private $command = 'whois';

    /** @var int */
    private $timeout;

    public function __construct($command = 'whois', $timeout = 60)
    {
        $this->setTimeout($timeout);
        $this->setCommandFullPath($command);
    }

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
        $this->timeout = max(0, (int) $seconds);

        return $this;
    }


    /**
     * @return string
     */
    public function getCommandFullPath(): string
    {
        return $this->command;
    }


    /**
     * @param string $path
     * @return $this
     */
    public function setCommandFullPath($path): self
    {
        $this->command = $path;
        return $this;
    }


    /**
     * @param string $whoisHost
     * @param string $query
     * @return string
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function loadText($whoisHost, $query): string
    {
        if (! gethostbynamel($whoisHost)) {
            throw new ConnectionException("Host is unreachable: $whoisHost");
        }

        $process = new Process([$this->command, '-h', $whoisHost, $query]);
        $process->setTimeout($this->getTimeout());
        $process->run();

        if (! $process->isSuccessful()) {
            throw new ConnectionException($process->getExitCodeText(), $process->getExitCode());
        }

        return $this->validateResponse(TextHelper::toUtf8($process->getOutput()));
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
