<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Asn;

use Iodev\Whois\Exceptions\ConnectionException;
use Iodev\Whois\Exceptions\WhoisException;
use Iodev\Whois\Loaders\ILoader;
use Iodev\Whois\Modules\Module;
use Iodev\Whois\Modules\ModuleType;

class AsnModule extends Module
{
    public function __construct(ILoader $loader)
    {
        parent::__construct(ModuleType::ASN, $loader);
    }

    /** @var AsnServer[] */
    private $servers = [];

    /**
     * @return AsnServer[]
     */
    public function getServers(): array
    {
        return $this->servers;
    }

    /**
     * @param AsnServer[] $servers
     */
    public function addServers(array $servers): static
    {
        return $this->setServers(array_merge($this->servers, $servers));
    }

    /**
     * @param AsnServer[] $servers
     */
    public function setServers(array $servers): static
    {
        $this->servers = $servers;
        return $this;
    }

    /**
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function lookupAsn(string $asn, AsnServer $server = null): AsnResponse
    {
        if ($server) {
            return $this->loadResponse($asn, $server);
        }
        list ($resp, ) = $this->loadData($asn);
        return $resp;
    }

    /**
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function loadAsnInfo(string $asn, AsnServer $server = null): ?AsnInfo
    {
        if ($server) {
            $resp = $this->loadResponse($asn, $server);
            return $server->parser->parseResponse($resp);
        }
        list (, $info) = $this->loadData($asn);
        return $info;
    }

    /**
     * @throws ConnectionException
     * @throws WhoisException
     */
    private function loadData(string $asn): array
    {
        $response = null;
        $info = null;
        $error = null;
        foreach ($this->servers as $s) {
            try {
                $response = $this->loadResponse($asn, $s);
                $info = $s->parser->parseResponse($response);
                if ($info) {
                    break;
                }
            } catch (ConnectionException $e) {
                $error = $e;
            }
        }
        if (!$response && $error) {
            throw $error;
        }
        return [$response, $info];
    }

    /**
     * @throws ConnectionException
     * @throws WhoisException
     */
    private function loadResponse(string $asn, AsnServer $server): AsnResponse
    {
        $host = $server->host;
        $query = $server->buildQuery($asn);
        $text = $this->getLoader()->loadText($host, $query);
        return new AsnResponse(
            $asn,
            $host,
            $query,
            $text,
        );
    }
}
