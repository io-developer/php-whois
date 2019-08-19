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
     * @return TldServer[]
     */
    public function createTldSevers(): array
    {
        $servers = [];
        foreach (Config::load("module.tld.servers") as $config) {
            $servers[] = $this->createTldSever($config);
        }
        return $servers;
    }

    /**
     * @param array $config
     * @return TldServer
     */
    public function createTldSever(array $config): TldServer
    {
        return new TldServer(
            $config['zone'] ?? '',
            $config['host'] ?? '',
            !empty($config['centralized']),
            $this->createTldSeverParser($config),
            $config['queryFormat'] ?? null
        );
    }

    /**
     * @param array $config
     * @return TldParser
     */
    public function createTldSeverParser(array $config): TldParser
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
        return TldParser::create()->setOptions($options);
    }
}
