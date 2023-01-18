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
use Iodev\Whois\Modules\Tld\TldServer;
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
                $instance = new TldModule($this->container->get(ILoader::class));
                $instance->setServers($this->createTldSevers());
                return $instance;
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
     * @param array|null $configs
     * @param TldParser|null $defaultParser
     * @return TldServer[]
     */
    protected function createTldSevers($configs = null): array
    {
        $configs = is_array($configs) ? $configs : Config::load("module.tld.servers");
        $servers = [];
        foreach ($configs as $config) {
            $servers[] = $this->createTldSever($config);
        }
        return $servers;
    }

    /**
     * @param array $config
     * @param TldParser|null $defaultParser
     * @return TldServer
     */
    protected function createTldSever(array $config): TldServer
    {
        $zone = $config['zone'] ?? '';
        if (empty($zone)) {
            throw new InvalidArgumentException("Zone must be specified");
        }
        $zone = rtrim('.' . trim($zone, '.'), '.');

        $host = $config['host'] ?? '';
        if (empty($host)) {
            throw new InvalidArgumentException("Host must be specified");
        }

        return new TldServer(
            $zone,
            $host,
            $config['centralized'] ?? false,
            $this->createTldSeverParser($config),
            $config['queryFormat'] ?? TldServer::DEFAULT_QUERY_FORMAT,
        );
    }

    /**
     * @param array $config
     * @param TldParser|null $defaultParser
     * @return TldParser
     */
    protected function createTldSeverParser(array $config): TldParser
    {
        $options = $config['parserOptions'] ?? [];
        if (isset($config['parserClass'])) {
            return $this->createTldParserByClass(
                $config['parserClass'],
                $config['parserType'] ?? null
            )->setOptions($options);
        }
        if (isset($config['parserType'])) {
            return $this->createTldParser($config['parserType'])->setOptions($options);
        }
        return $this->createTldParser()->setOptions($options);
    }

    /**
     * @param string $type
     * @return TldParser
     */
    protected function createTldParser($type = null)
    {
        $type = $type ? $type : TldParser::AUTO;
        $d = [
            TldParser::AUTO => AutoParser::class,
            TldParser::COMMON => CommonParser::class,
            TldParser::COMMON_FLAT => CommonParser::class,
            TldParser::BLOCK => BlockParser::class,
            TldParser::INDENT => IndentParser::class,
            TldParser::INDENT_AUTOFIX => IndentParser::class,
        ];
        return $this->createTldParserByClass($d[$type], $type);
    }

    /**
     * @param string $className
     * @param string $configType
     * @return TldParser
     */
    protected function createTldParserByClass($className, $configType = null)
    {
        $configType = empty($configType) ? TldParser::AUTO : $configType;
        $config = $this->getTldParserConfigByType($configType);

        /* @var $parser TldParser */
        $parser = new $className();
        $parser->setConfig($config);
        if ($parser->getType() == TldParser::AUTO) {
            $this->setupTldAutoParser($parser, $config);
        }

        return $parser;
    }

    /**
     * @param AutoParser $parser
     * @param array $config
     */
    protected function setupTldAutoParser(AutoParser $parser, $config = [])
    {
        /* @var $autoParser AutoParser */
        foreach ($config['parserTypes'] ?? [] as $type) {
            $parser->addParser($this->createTldParser($type));
        }
    }

    /**
     * @param string $type
     * @return array
     */
    protected function getTldParserConfigByType($type)
    {
        if ($type == TldParser::COMMON_FLAT) {
            $type = TldParser::COMMON;
            $extra = ['isFlat' => true];
        }
        if ($type == TldParser::INDENT_AUTOFIX) {
            $type = TldParser::INDENT;
            $extra = ['isAutofix' => true];
        }
        $config = Config::load("module.tld.parser.$type");
        return empty($extra) ? $config : array_merge($config, $extra);
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
