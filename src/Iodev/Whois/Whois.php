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
        list (, $info) = $this->loadDomainDataFrom($server, $domain);
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
        list ($response) = $this->loadDomainDataFrom($server, $domain);
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
     * @throws ConnectionException
     */
    private function loadDomainDataFrom(Server $server, $domain)
    {
        $p = $server->getParser();

        /* @var $response Response */
        /* @var $error ConnectionException */
        list($response, $error) = $this->loadDomainResponse($server, $server->getHost(), $domain);

        $info = $p->parseResponse($response);
        if (!$info) {
            list($response, $error) = $this->loadDomainResponse($server, $server->getHost(), $domain, true);
            $info = $p->parseResponse($response);
        }
        if ($error) {
            throw $error;
        }

        if ($info
            && $info->getWhoisServer()
            && $info->getWhoisServer() != $server->getHost()
            && !$server->isCentralized()
        ) {
            list($tmpResponse, $error) = $this->loadDomainResponse($server, $info->getWhoisServer(), $domain, true);
            $tmpInfo = $p->parseResponse($tmpResponse);
            if ($tmpInfo && empty($error)) {
                $response = $tmpResponse;
                $info = $tmpInfo;
            }
        }
        return [ $response, $info ];
    }

    /**
     * @param Server $server
     * @param string $whoisHost
     * @param string $domain
     * @param bool $strict
     * @return array
     */
    private function loadDomainResponse(Server $server, $whoisHost, $domain, $strict = false)
    {
        $error = null;
        try {
            $text = $this->loader->loadText($whoisHost, $server->buildDomainQuery($domain, $strict));
        } catch (ConnectionException $e) {
            $error = $e;
            $text = "";
        }
        return [ new Response($domain, $text, $whoisHost), $error ];
    }
}
