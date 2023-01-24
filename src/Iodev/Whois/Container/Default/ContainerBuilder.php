<?php

declare(strict_types=1);

namespace Iodev\Whois\Container\Default;


use \InvalidArgumentException;

use Iodev\Whois\Config;
use Iodev\Whois\Loaders\ILoader;
use Iodev\Whois\Loaders\SocketLoader;
use Iodev\Whois\Modules\Asn\AsnModule;
use Iodev\Whois\Modules\Asn\AsnParser;
use Iodev\Whois\Modules\Asn\AsnServer;
use Iodev\Whois\Modules\Tld\Parsers\AutoParser;
use Iodev\Whois\Modules\Tld\Parsers\BlockParser;
use Iodev\Whois\Modules\Tld\Parsers\CommonParser;
use Iodev\Whois\Modules\Tld\Parsers\IndentParser;
use Iodev\Whois\Modules\Tld\TldModule;
use Iodev\Whois\Modules\Tld\TldParser;
use Iodev\Whois\Modules\Tld\TldParserProvider;
use Iodev\Whois\Modules\Tld\TldParserProviderInterface;
use Iodev\Whois\Modules\Tld\TldServer;
use Iodev\Whois\Modules\Tld\TldServerProvider;
use Iodev\Whois\Modules\Tld\TldServerProviderInterface;
use Iodev\Whois\Punycode\IPunycode;
use Iodev\Whois\Punycode\IntlPunycode;
use Iodev\Whois\Whois;


class ContainerBuilder
{
    protected $container;

    public function __construct()
    {
        $this->container = new Container();
    }

    public function getContainer(): Container
    {
        return $this->container;
    }

    public function configure(): static
    {
        $this->container->bindMany([
            Container::ID_COMMON_CLASS_INSTANTIATOR => fn($clName) => new $clName(),

            IPunycode::class => fn() => new IntlPunycode(),
            ILoader::class => fn() => new SocketLoader(),

            Whois::class => function() {
                $instance = new Whois(
                    $this->container,
                    $this->container->get(TldModule::class),
                    $this->container->get(AsnModule::class),
                );
                return $instance;
            },

            TldModule::class => function() {
                /** @var TldServerProviderInterface */
                $provider = $this->container->get(TldServerProviderInterface::class);
                $servers = $provider->getList();

                $instance = new TldModule($this->container->get(ILoader::class));
                $instance->setServers($servers);

                return $instance;
            },

            TldServerProviderInterface::class => function() {
                return $this->container->get(TldServerProvider::class);
            },

            TldServerProvider::class => function() {
                return new TldServerProvider(
                    $this->container->get(TldParserProviderInterface::class),
                );
            },

            TldParserProviderInterface::class => function() {
                return $this->container->get(TldParserProvider::class);
            },

            TldParserProvider::class => function() {
                return new TldParserProvider(
                    $this->container,
                );
            },

            AsnModule::class => function() {
                $instance = new AsnModule($this->container->get(ILoader::class));
                $instance->setServers($this->createAsnSevers());
                return $instance;
            },

            AsnParser::class => fn() => new AsnParser(),
        ]);

        return $this;
    }

    /**
     * @param array $configs|null
     * @param AsnParser $defaultParser
     * @return AsnServer[]
     */
    protected function createAsnSevers($configs = null): array
    {
        $configs = is_array($configs) ? $configs : Config::load("module.asn.servers");
        $servers = [];
        foreach ($configs as $config) {
            $servers[] = $this->createAsnSever($config);
        }
        return $servers;
    }

    /**
     * @param array $config
     * @param AsnParser $defaultParser
     * @return AsnServer
     */
    protected function createAsnSever($config)
    {
        $host = $config['host'] ?? '';
        if (empty($host)) {
            throw new InvalidArgumentException("Host must be specified");
        }
        return new AsnServer(
            $host,
            $this->container->get($config['parserClass'] ?? AsnParser::class),
            $config['queryFormat'] ?? AsnServer::DEFAULT_QUERY_FORMAT,
        );
    }
}
