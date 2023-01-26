<?php

declare(strict_types=1);

namespace Iodev\Whois\Loaders;

use Iodev\Whois\Exceptions\ConnectionException;

class FakeSocketLoader extends SocketLoader
{
    public string $text = "";
    public bool $failOnConnect = false;

    public function loadText(string $whoisHost, string $query): string
    {
        if ($this->failOnConnect) {
            throw new ConnectionException("Fake connection fault");
        }
        return $this->text;
    }
}
