<?php

namespace Iodev\Whois\Modules\Tld;

use Iodev\Whois\Config;

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
            self::COMMON => '\Iodev\Whois\Modules\Tld\Parsers\CommonParser',
            self::COMMON_FLAT => '\Iodev\Whois\Modules\Tld\Parsers\CommonParser',
            self::BLOCK => '\Iodev\Whois\Modules\Tld\Parsers\BlockParser',
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
     * @param DomainResponse $response
     * @return DomainInfo
     */
    abstract public function parseResponse(DomainResponse $response);
}
