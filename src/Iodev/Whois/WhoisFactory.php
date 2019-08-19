<?php

namespace Iodev\Whois;

use Iodev\Whois\Loaders\ILoader;
use Iodev\Whois\Loaders\SocketLoader;
use Iodev\Whois\Modules\Asn\AsnModule;
use Iodev\Whois\Modules\Asn\AsnServer;
use Iodev\Whois\Modules\Tld\TldModule;
use Iodev\Whois\Modules\Tld\TldParser;
use Iodev\Whois\Modules\Tld\TldServer;

class WhoisFactory implements IWhoisFactory
{
    /**
     * @return WhoisFactory
     */
    public static function getInstance(): WhoisFactory
    {
        static $instance;
        if (!$instance) {
            $instance = new static();
        }
        return $instance;
    }

    /**
     * @param ILoader|null $loader
     * @return Whois
     */
    public function createWhois(ILoader $loader = null): Whois
    {
        $whois = new Whois($loader ?: $this->createLoader());
        $whois->setFactory($this);
        return $whois;
    }

    /**
     * @return ILoader
     */
    public function createLoader(): ILoader
    {
        return new SocketLoader();
    }

    /**
     * @param ILoader $loader
     * @param AsnServer[] $servers
     * @return AsnModule
     */
    public function createAsnModule(ILoader $loader = null, $servers = null): AsnModule
    {
        $m = new AsnModule($loader);
        $m->setServers($servers ?: AsnServer::fromDataList(Config::load("module.asn.servers")));
        return $m;
    }

    /**
     * @param ILoader $loader
     * @param TldServer[] $servers
     * @return TldModule
     */
    public function createTldModule(ILoader $loader = null, $servers = null): TldModule
    {
        $m = new TldModule($loader);
        $m->setServers($servers ?: $this->createTldSevers());
        return $m;
    }

    /**
     * @param array|null $configs
     * @param TldParser|null $defaultParser
     * @return TldServer[]
     */
    public function createTldSevers($configs = null, TldParser $defaultParser = null): array
    {
        $configs = is_array($configs) ? $configs : Config::load("module.tld.servers");
        $defaultParser = $defaultParser ?: TldParser::create();
        $servers = [];
        foreach ($configs as $config) {
            $servers[] = $this->createTldSever($config, $defaultParser);
        }
        return $servers;
    }

    /**
     * @param array $config
     * @param TldParser|null $defaultParser
     * @return TldServer
     */
    public function createTldSever(array $config, TldParser $defaultParser = null): TldServer
    {
        return new TldServer(
            $config['zone'] ?? '',
            $config['host'] ?? '',
            !empty($config['centralized']),
            $this->createTldSeverParser($config, $defaultParser),
            $config['queryFormat'] ?? null
        );
    }

    /**
     * @param array $config
     * @param TldParser|null $defaultParser
     * @return TldParser
     */
    public function createTldSeverParser(array $config, TldParser $defaultParser = null): TldParser
    {
        $options = $config['parserOptions'] ?? [];
        if (isset($config['parserClass'])) {
            return TldParser::createByClass(
                $config['parserClass'],
                $config['parserType'] ?? null
            )->setOptions($options);
        }
        if (isset($config['parserType'])) {
            return TldParser::create($config['parserType'])->setOptions($options);
        }
        return $defaultParser ?: TldParser::create()->setOptions($options);
    }
}
