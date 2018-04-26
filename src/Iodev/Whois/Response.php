<?php

namespace Iodev\Whois;

class Response
{
    /**
     * @param string $domain
     * @param string $text
     * @param string $whoisHost
     * @return Response
     */
    public static function createDomainResponse($domain, $text, $whoisHost = "")
    {
        return new Response(ResponseType::DOMAIN, $domain, $text, $whoisHost);
    }

    public function __construct($type, $domain = "", $text = "", $whoisHost = "")
    {
        $this->type = strval($type);
        $this->domain = strval($domain);
        $this->text = strval($text);
        $this->whoisHost = strval($whoisHost);
    }

    /** @var string */
    private $type;

    /** @var string */
    private $domain;
    
    /** @var string */
    private $text;

    /** @var string */
    private $whoisHost;

    /**
     * @return string
     */
    public function getType()
    {
        return $this->type;
    }

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
