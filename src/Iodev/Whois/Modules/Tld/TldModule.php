<?php

namespace Iodev\Whois\Modules\Tld;

use Iodev\Whois\Config;
use Iodev\Whois\Exceptions\ConnectionException;
use Iodev\Whois\Exceptions\ServerMismatchException;
use Iodev\Whois\Helpers\DomainHelper;
use Iodev\Whois\Loaders\ILoader;
use Iodev\Whois\Modules\Module;
use Iodev\Whois\Modules\ModuleType;
use Iodev\Whois\Response;

class TldModule extends Module
{
    /**
     * @param ILoader $loader
     * @param array $servers
     * @return self
     */
    public static function create(ILoader $loader = null, $servers = null)
    {
        $m = new self($loader);
        $m->setServers($servers ?: Server::fromDataList(Config::getServersData()));
        return $m;
    }

    /**
     * @param ILoader $loader
     */
    public function __construct(ILoader $loader)
    {
        parent::__construct(ModuleType::TLD, $loader);
    }

    /** @var Server[] */
    private $servers = [];

    /**
     * @return Server[]
     */
    public function getServers()
    {
        return $this->servers;
    }

    /**
     * @param Server[] $servers
     * @return $this
     */
    public function addServers($servers)
    {
        return $this->setServers(array_merge($this->servers, $servers));
    }

    /**
     * @param Server[] $servers
     * @return $this
     */
    public function setServers($servers)
    {
        $this->servers = $servers;
        usort($this->servers, function(Server $a, Server $b) {
            return strlen($b->getZone()) - strlen($a->getZone());
        });
        return $this;
    }

    /**
     * @param string $domain
     * @param bool $quiet
     * @return Server[]
     * @throws ServerMismatchException
     */
    public function matchServers($domain, $quiet = false)
    {
        $servers = [];
        $maxlen = 0;
        foreach ($this->servers as $server) {
            $zone = $server->getZone();
            if (strlen($zone) < $maxlen) {
                break;
            }
            if ($server->isDomainZone($domain)) {
                $servers[] = $server;
                $maxlen = max($maxlen, strlen($zone));
            }
        }
        if (!$quiet && empty($servers)) {
            throw new ServerMismatchException("No servers matched for domain '$domain'");
        }
        return $servers;
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
     * @param Server $server
     * @return Response
     * @throws ServerMismatchException
     * @throws ConnectionException
     */
    public function lookupDomain($domain, Server $server = null)
    {
        $servers = $server ? [$server] : $this->matchServers($domain);
        list ($response) = $this->loadDomainData($domain, $servers);
        return $response;
    }

    /**
     * @param string $domain
     * @param Server $server
     * @return DomainInfo
     * @throws ServerMismatchException
     * @throws ConnectionException
     */
    public function loadDomainInfo($domain, Server $server = null)
    {
        $servers = $server ? [$server] : $this->matchServers($domain);
        list (, $info) = $this->loadDomainData($domain, $servers);
        return $info;
    }

    /**
     * @param Server $server
     * @param string $domain
     * @param bool $strict
     * @param string $host
     * @return Response
     * @throws ConnectionException
     */
    public function loadResponse(Server $server, $domain, $strict = false, $host = null)
    {
        $host = $host ?: $server->getHost();
        $query = $server->buildDomainQuery($domain, $strict);
        $text = $this->getLoader()->loadText($host, $query);
        return new Response(ModuleType::TLD, $domain, $text, $host);
    }

    /**
     * @param string $domain
     * @param Server[] $servers
     * @return array
     * @throws ConnectionException
     */
    private function loadDomainData($domain, $servers)
    {
        $domain = DomainHelper::toAscii($domain);
        $response = null;
        $info = null;
        foreach ($servers as $server) {
            $this->loadParsedTo($response, $info, $server, $domain);
            if ($info) {
                break;
            }
        }
        return [ $response, $info ];
    }

    /**
     * @param $outResponse
     * @param DomainInfo $outInfo
     * @param Server $server
     * @param $domain
     * @param $strict
     * @param $host
     * @param $lastError
     * @throws ConnectionException
     */
    private function loadParsedTo(&$outResponse, &$outInfo, $server, $domain, $strict = false, $host = null, $lastError = null)
    {
        try {
            $outResponse = $this->loadResponse($server, $domain, $strict, $host);
            $outInfo = $server->getParser()->parseResponse($outResponse);
        } catch (ConnectionException $e) {
            $lastError = $lastError ?: $e;
        }
        if (!$outInfo && $lastError && $host == $server->getHost() && $strict) {
            throw $lastError;
        }
        if (!$strict && !$outInfo) {
            $this->loadParsedTo($tmpResponse, $tmpInfo, $server, $domain, true, $host, $lastError);
            $outResponse = $tmpInfo ? $tmpResponse : $outResponse;
            $outInfo = $tmpInfo ?: $outInfo;
        }
        if (!$outInfo || $host == $outInfo->getWhoisServer()) {
            return;
        }
        $host = $outInfo->getWhoisServer();
        if ($host && $host != $server->getHost() && !$server->isCentralized()) {
            $this->loadParsedTo($tmpResponse, $tmpInfo, $server, $domain, false, $host, $lastError);
            $outResponse = $tmpInfo ? $tmpResponse : $outResponse;
            $outInfo = $tmpInfo ?: $outInfo;
        }
    }
}
