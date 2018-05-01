<?php

namespace Iodev\Whois\Modules\Asn;

use Iodev\Whois\Exceptions\ConnectionException;
use Iodev\Whois\Loaders\ILoader;
use Iodev\Whois\Modules\Module;
use Iodev\Whois\Modules\ModuleType;

class AsnModule extends Module
{
    /**
     * @param ILoader $loader
     * @param AsnServer $server
     * @return self
     */
    public static function create(ILoader $loader = null, AsnServer $server = null)
    {
        $server = $server ?: new AsnServer("whois.ripe.net", new AsnParser());
        return new self($loader, $server);
    }

    /**
     * @param ILoader $loader
     * @param AsnServer $server
     */
    public function __construct(ILoader $loader, AsnServer $server)
    {
        parent::__construct(ModuleType::ASN, $loader);
        $this->server = $server;
    }

    /** @var AsnServer */
    private $server;

    /**
     * @return AsnServer
     */
    public function getServer()
    {
        return $this->server;
    }

    /**
     * @param AsnServer $server
     * @return $this
     */
    public function setServer(AsnServer $server)
    {
        $this->server = $server;
        return $this;
    }

    /**
     * @param string $asn
     * @return AsnResponse
     * @throws ConnectionException
     */
    public function lookupAsn($asn)
    {
        $host = $this->server->getHost();
        $query = $this->server->buildQuery($asn);
        $text = $this->getLoader()->loadText($host, $query);
        return new AsnResponse($asn, $query, $text, $host);
    }

    /**
     * @param $asn
     * @return AsnInfo
     * @throws ConnectionException
     */
    public function loadAsnInfo($asn)
    {
        $resp = $this->lookupAsn($asn);
        return $this->server->getParser()->parseResponse($resp);
    }
}
