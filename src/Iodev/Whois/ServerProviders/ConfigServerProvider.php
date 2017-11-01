<?php

namespace Iodev\Whois\ServerProviders;

use Iodev\Whois\Helpers\DomainHelper;
use Iodev\Whois\Server;

class ConfigServerProvider implements IServerProvider
{
    /**
     * @param array $configs  { zone: "", host: "", [ centralized: true|false ], [ parser: "\Class" ] }
     */
    public function __construct($configs)
    {
        $this->addConfigs($configs);
    }

    /** @var array  sorted by zone */
    private $configs = [];

    /**
     * @param $config
     * @return $this
     */
    public function addConfig($config)
    {
        return $this->addConfigs([ $config ]);
    }

    /**
     * @param $configs
     * @return $this
     */
    public function addConfigs($configs)
    {
        $this->configs = array_merge($this->configs, $configs);
        usort($this->configs, function($a, $b) {
            return strcmp($b["zone"], $a["zone"]);
        });
        return $this;
    }

    /**
     * @param string $domain
     * @return Server[]
     */
    public function getServersForDomain($domain)
    {
        $servers = [];
        foreach ($this->getConfigsForDomain($domain) as $config) {
            $servers[] = $this->createServerFromConfig($config);
        }
        return $servers;
    }

    /**
     * @param string $domain
     * @return array
     */
    public function getConfigsForDomain($domain)
    {
        $configs = [];
        $maxlen = 0;
        foreach ($this->configs as $config) {
            $zone = $config["zone"];
            if (strlen($zone) < $maxlen) {
                break;
            }
            if (DomainHelper::belongsToZone($domain, $zone)) {
                $configs[] = $config;
                $maxlen = max($maxlen, strlen($zone));
            }
        }
        return $configs;
    }

    /**
     * @param array $config
     * @return Server
     */
    public function createServerFromConfig($config)
    {
        $parserClass = isset($config['parser'])
            ? $config['parser']
            : '\Iodev\Whois\Parsers\CommonParser';

        return new Server(
            $config['zone'],
            !empty($config['centralized']),
            $config['host'],
            new $parserClass()
        );
    }
}
