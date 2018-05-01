<?php

namespace Iodev\Whois;

class Response
{
    public function __construct($query = "", $text = "", $host = "")
    {
        $this->query = strval($query);
        $this->text = strval($text);
        $this->host = strval($host);
    }

    /** @var string */
    private $query;
    
    /** @var string */
    private $text;

    /** @var string */
    private $host;

    /**
     * @return string
     */
    public function getQuery()
    {
        return $this->query;
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
    public function getHost()
    {
        return $this->host;
    }
}
