<?php

namespace Iodev\Whois;

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
    }

    /** @var ServerProvider */
    private $serverProvider;

    /** @var ILoader */
    private $loader;

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
     */
    public function isDomainAvailable($domain)
    {
        return !$this->loadDomainInfo($domain);
    }

    /**
     * @param string $domain
     * @return DomainInfo
     * @throws ServerMismatchException
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
     */
    public function loadDomainInfoFrom(Server $server, $domain)
    {
        list (, $info) = $this->loadDomainDataFrom($server, $domain);
        return $info;
    }

    /**
     * @param string $domain
     * @return Response
     * @throws ServerMismatchException
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
     */
    public function lookupDomainFrom(Server $server, $domain)
    {
        list ($response) = $this->loadDomainDataFrom($server, $domain);
        return $response;
    }

    /**
     * @param string $domain
     * @return array
     * @throws ServerMismatchException
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
            list ($response, $info) = $this->loadDomainDataFrom($server, $domain);
            if ($info) {
                return [ $response, $info ];
            }
        }
        return [ $response, $info ];
    }

    /**
     * @param Server $server
     * @param string $domain
     * @return array
     */
    private function loadDomainDataFrom(Server $server, $domain)
    {
        $p = $server->getParser();
        $response = $this->loader->loadResponse($server->getHost(), $domain);
        $info = $p->parseResponse($response);
        if (!$info) {
            $response = $this->loader->loadResponse($server->getHost(), $domain, true);
            $info = $p->parseResponse($response);
        }
        if ($info
            && $info->getWhoisServer()
            && $info->getWhoisServer() != $server->getHost()
            && !$server->isCentralized()
        ) {
            $tmpResponse = $this->loader->loadResponse($info->getWhoisServer(), $domain);
            $tmpInfo = $p->parseResponse($tmpResponse);
            if ($tmpInfo) {
                $response = $tmpResponse;
                $info = $tmpInfo;
            }
        }
        return [ $response, $info ];
    }
}
