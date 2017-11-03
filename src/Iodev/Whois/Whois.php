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
     * @return DomainInfo
     * @throws ServerMismatchException
     */
    public function loadInfo($domain)
    {
        $domain = DomainHelper::toAscii($domain);
        $servers = $this->serverProvider->match($domain);
        if (empty($servers)) {
            throw new ServerMismatchException("No servers matched for domain '$domain'");
        }
        foreach ($servers as $server) {
            $info = $this->loadInfoFrom($server, $domain);
            if ($info) {
                return $info;
            }
        }
        return null;
    }

    /**
     * @param Server $server
     * @param string $domain
     * @return DomainInfo
     */
    public function loadInfoFrom(Server $server, $domain)
    {
        $l = $this->loader;
        $p = $server->getParser();
        $info = $p->parseResponse($l->loadResponse($server->getHost(), $domain));
        if (!$info) {
            $info = $p->parseResponse($l->loadResponse($server->getHost(), $domain, true));
        }
        if ($info && $info->getWhoisServer() && !$server->isCentralized()) {
            $tmpInfo = $p->parseResponse($l->loadResponse($info->getWhoisServer(), $domain));
            $info = $tmpInfo ? $tmpInfo : $info;
        }
        return $info;
    }
}
