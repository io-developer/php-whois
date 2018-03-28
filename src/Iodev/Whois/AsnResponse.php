<?php


namespace Iodev\Whois;


class AsnResponse
{
    public function __construct($asn = "", $text = "", $whoisHost = "")
    {
        $this->asn = strval($asn);
        $this->text = strval($text);
        $this->whoisHost = strval($whoisHost);
    }

    /** @var string */
    private $asn;

    /** @var string */
    private $text;

    /** @var string */
    private $whoisHost;

    /**
     * @return string
     */
    public function getDomain()
    {
        return $this->asn;
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
