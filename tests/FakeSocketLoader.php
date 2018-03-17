<?php

use Iodev\Whois\Exceptions\ConnectionException;
use Iodev\Whois\Loaders\SocketLoader;

class FakeSocketLoader extends SocketLoader
{
    public $text = "";
    public $failOnConnect = false;

    public function loadText($whoisHost, $query)
    {
        if ($this->failOnConnect) {
            throw new ConnectionException("Fake connection fault");
        }
        return $this->text;
    }
}
