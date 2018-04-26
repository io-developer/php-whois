<?php

namespace Iodev\Whois;

use Iodev\Whois\Exceptions\ConnectionException;
use Iodev\Whois\Info\DomainInfo;
use Iodev\Whois\Loaders\ILoader;

class Fetcher
{
    public function __construct(ILoader $loader)
    {
        $this->loader = $loader;
    }

    /** @var ILoader */
    private $loader;

    /**
     * @return ILoader
     */
    public function getLoader()
    {
        return $this->loader;
    }

    /**
     * @param Server $server
     * @param string $domain
     * @param bool $strict
     * @param string $host
     * @return Response
     * @throws ConnectionException
     */
    public function fetchDomainResponse(Server $server, $domain, $strict = false, $host = null)
    {
        $host = $host ?: $server->getHost();
        $text = $this->loader->loadText($host, $server->buildDomainQuery($domain, $strict));
        return Response::createDomainResponse($domain, $text, $host);
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
    public function fetchDomainParsedTo(&$outResponse, &$outInfo, $server, $domain, $strict = false, $host = null, $lastError = null)
    {
        try {
            $outResponse = $this->fetchDomainResponse($server, $domain, $strict, $host);
            $outInfo = $server->getParser()->parseResponse($outResponse);
        } catch (ConnectionException $e) {
            $lastError = $lastError ?: $e;
        }
        if (!$outInfo && $lastError && $host == $server->getHost() && $strict) {
            throw $lastError;
        }
        if (!$strict && !$outInfo) {
            $this->fetchDomainParsedTo($tmpResponse, $tmpInfo, $server, $domain, true, $host, $lastError);
            $outResponse = $tmpInfo ? $tmpResponse : $outResponse;
            $outInfo = $tmpInfo ?: $outInfo;
        }
        if (!$outInfo || $host == $outInfo->getWhoisServer()) {
            return;
        }
        $host = $outInfo->getWhoisServer();
        if ($host && $host != $server->getHost() && !$server->isCentralized()) {
            $this->fetchDomainParsedTo($tmpResponse, $tmpInfo, $server, $domain, false, $host, $lastError);
            $outResponse = $tmpInfo ? $tmpResponse : $outResponse;
            $outInfo = $tmpInfo ?: $outInfo;
        }
    }
}
