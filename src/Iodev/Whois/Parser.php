<?php

namespace Iodev\Whois;

abstract class Parser
{
    const COMMON = 'common';
    const COMMON_FLAT = 'commonFlat';
    const BLOCK = 'block';

    /**
     * @param string $type
     * @return Parser
     */
    public static function create($type = null)
    {
        $type = $type ? $type : self::COMMON;
        $d = [
            self::COMMON => '\Iodev\Whois\Parsers\CommonParser',
            self::COMMON_FLAT => '\Iodev\Whois\Parsers\CommonParser',
            self::BLOCK => '\Iodev\Whois\Parsers\BlockParser',
        ];
        return self::createByClass($d[$type], $type);
    }

    /**
     * @param string $className
     * @param string $configType
     * @return Parser
     */
    public static function createByClass($className, $configType = null)
    {
        /* @var $p Parser */
        $p = new $className();
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
