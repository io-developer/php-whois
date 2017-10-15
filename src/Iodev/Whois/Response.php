<?php

namespace Iodev\Whois;

class Response
{
    public function __construct($domain = "", $text = "", $whoisHost = "")
    {
        $this->domain = strval($domain);
        $this->text = strval($text);
        $this->whoisHost = strval($whoisHost);
    }

    /** @var string */
    private $domain;
    
    /** @var string */
    private $text;

    /** @var string */
    private $whoisHost;

    /**
     * @return string
     */
    public function getDomain()
    {
        return $this->domain;
    }

    /**
     * @return string
     */
    public function getText()
    {
        return $this->text;
    }

    /**
     * @return string
     */
    public function getWhoisHost()
    {
        return $this->whoisHost;
    }
}
