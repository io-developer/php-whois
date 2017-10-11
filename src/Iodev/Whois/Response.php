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
    public $domain;
    
    /** @var string */
    public $text;
}
