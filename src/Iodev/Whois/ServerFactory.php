<?php

namespace Iodev\Whois;

use Iodev\Whois\Parsers\IParser;

class ServerFactory
{
    /** @var array */
    private static $configs = null;

    /** @var IParser[] */
    private static $parserPool = [];

    /**
     * @return array
     */
    private static function getConfigs()
    {
        if (!isset(self::$configs)) {
            self::$configs = require __DIR__ . '/default_servers.php';
        }
        return self::$configs;
    }

    /**
     * @return Server[]
     */
    public static function createAll()
    {
        $servers = [];
        foreach (self::getConfigs() as $conf) {
            $servers[] = self::createFromConfig($conf);
        }
        return $servers;
    }

    /**
     * @param string[] $zones
     * @return Server[]
     */
    public static function createSome($zones)
    {
        $hash = array_flip($zones);
        $servers = [];
        foreach (self::getConfigs() as $conf) {
            if (isset($hash[$conf["zone"]])) {
                $servers[] = self::createFromConfig($conf);
            }
        }
        return $servers;
    }

    /**
     * @param $conf
     * @return Server
     */
    public static function createFromConfig($conf)
    {
        $server = new Server($conf['zone']);
        $server->host = $conf['host'];
        $server->isCentralized = $conf['centralized'];

        $parserClass = $conf['parser'];
        if (isset(self::$parserPool[$parserClass])) {
            $server->parser = self::$parserPool[$parserClass];
        } else {
            $server->parser = new $parserClass();
            self::$parserPool[$parserClass] = $server->parser;
        }

        return $server;
    }
}
