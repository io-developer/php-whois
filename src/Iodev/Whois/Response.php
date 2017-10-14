<?php

namespace Iodev\Whois;

class Response
{
    /**
     * @param string $domain
     * @param string $text
     */
    public function __construct($domain = "", $text = "")
    {
        $this->domain = $domain;
        $this->text = $text;
    }

    /** @var string */
    private $domain;
    
    /** @var string */
    private $text;

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
}
