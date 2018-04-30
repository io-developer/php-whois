<?php

namespace Iodev\Whois;

use Iodev\Whois\Modules\ModuleType;

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
        return new Response(ModuleType::TLD, $domain, $text, $whoisHost);
    }

    public function __construct($type, $target = "", $text = "", $whoisHost = "")
    {
        $this->type = strval($type);
        $this->target = strval($target);
        $this->text = strval($text);
        $this->whoisHost = strval($whoisHost);
    }

    /** @var string */
    private $type;

    /** @var string */
    private $target;
    
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
    public function getTarget()
    {
        return $this->target;
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
