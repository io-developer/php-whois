<?php

namespace Iodev\Whois;

use Iodev\Whois\Exceptions\ConnectionException;
use Iodev\Whois\Exceptions\ServerMismatchException;
use Iodev\Whois\Helpers\DomainHelper;
use Iodev\Whois\Loaders\ILoader;
use Iodev\Whois\Loaders\SocketLoader;

class Whois
{
    /**
     * @param ServerProvider $provider
     * @param ILoader $loader
     * @return Whois
     */
    public static function create(ServerProvider $provider = null, ILoader $loader = null)
    {
        return new Whois(
            $provider ?: new ServerProvider(Server::fromDataList(Config::getServersData())),
            $loader ?: new SocketLoader()
        );
    }

    public function __construct(ServerProvider $provider, ILoader $loader)
    {
        $this->serverProvider = $provider;
        $this->loader = $loader;
        $this->fetcher = new Fetcher($loader);
    }

    /** @var ServerProvider */
    private $serverProvider;

    /** @var ILoader */
    private $loader;

    /** @var Fetcher */
    private $fetcher;

    /**
     * @return ServerProvider
     */
    public function getServerProvider()
    {
        return $this->serverProvider;
    }

    /**
     * @return ILoader
     */
    public function getLoader()
    {
        return $this->loader;
    }

    /**
     * @param string $domain
     * @return bool
     * @throws ServerMismatchException
     * @throws ConnectionException
     */
    public function isDomainAvailable($domain)
    {
        return !$this->loadDomainInfo($domain);
    }

    /**
     * @param string $domain
     * @return DomainInfo
     * @throws ServerMismatchException
     * @throws ConnectionException
     */
    public function loadDomainInfo($domain)
    {
        list (, $info) = $this->loadDomainData($domain);
        return $info;
    }

    /**
     * @param Server $server
     * @param string $domain
     * @return DomainInfo
     * @throws ConnectionException
     */
    public function loadDomainInfoFrom(Server $server, $domain)
    {
        $this->fetcher->fetchDomainParsedTo($response, $info, $server, $domain);
        return $info;
    }

    /**
     * @param string $domain
     * @return Response
     * @throws ServerMismatchException
     * @throws ConnectionException
     */
    public function lookupDomain($domain)
    {
        list ($response) = $this->loadDomainData($domain);
        return $response;
    }

    /**
     * @param Server $server
     * @param string $domain
     * @return Response
     * @throws ConnectionException
     */
    public function lookupDomainFrom(Server $server, $domain)
    {
        $this->fetcher->fetchDomainParsedTo($response, $info, $server, $domain);
        return $response;
    }

    /**
     * @param string $domain
     * @return array
     * @throws ServerMismatchException
     * @throws ConnectionException
     */
    private function loadDomainData($domain)
    {
        $domain = DomainHelper::toAscii($domain);
        $servers = $this->serverProvider->match($domain);
        if (empty($servers)) {
            throw new ServerMismatchException("No servers matched for domain '$domain'");
        }
        $response = null;
        $info = null;
        foreach ($servers as $server) {
            $this->fetcher->fetchDomainParsedTo($response, $info, $server, $domain);
            if ($info) {
                return [ $response, $info ];
            }
        }
        return [ $response, $info ];
    }
}
