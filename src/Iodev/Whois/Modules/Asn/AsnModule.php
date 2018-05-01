<?php

namespace Iodev\Whois\Modules\Asn;

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
        $server = $server ?: new AsnServer();
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
     * @return AsnResponse
     */
    public function lookupAsn()
    {
        return new AsnResponse();
    }

    /**
     * @return AsnInfo
     */
    public function loadAsnInfo()
    {
        return new AsnInfo();
    }
}
