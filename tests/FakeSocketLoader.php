<?php

use Iodev\Whois\Exceptions\ConnectionException;
use Iodev\Whois\Loaders\SocketLoader;
use Iodev\Whois\Response;

class FakeSocketLoader extends SocketLoader
{
    public $text = "";
    public $failOnConnect = false;

    public function loadResponse($whoisHost, $domain, $strict = false)
    {
        if ($this->failOnConnect) {
            throw new ConnectionException("Fake connection fault");
        }
        return new Response($domain, $this->text, $whoisHost);
    }
}
