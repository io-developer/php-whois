<?php

namespace Iodev\Whois;

use Iodev\Whois\Parsers\CommonParser;

abstract class Parser
{
    /**
     * @param string $className
     * @param string $configType
     * @return Parser
     */
    public static function create($className = null, $configType = null)
    {
        /* @var $p Parser */
        $p = !empty($className) ? new $className() : new CommonParser();
        $p->setConfig(Config::getParserConfig($configType));
        return $p;
    }

    /**
     * @param array $cfg
     * @return $this
     */
    abstract public function setConfig($cfg);

    /**
     * @param Response $response
     * @return DomainInfo
     */
    abstract public function parseResponse(Response $response);
}
