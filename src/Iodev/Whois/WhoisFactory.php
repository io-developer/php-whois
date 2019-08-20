<?php

namespace Iodev\Whois;

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
        $m->setServers($servers ?: $this->createAsnSevers(Config::load("module.asn.servers")));
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
        $defaultParser = $defaultParser ?: $this->createTldParser();
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
            return $this->createTldParserByClass(
                $config['parserClass'],
                $config['parserType'] ?? null
            )->setOptions($options);
        }
        if (isset($config['parserType'])) {
            return $this->createTldParser($config['parserType'])->setOptions($options);
        }
        return $defaultParser ?: $this->createTldParser()->setOptions($options);
    }

    /**
     * @param string $type
     * @return TldParser
     */
    public function createTldParser($type = null)
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
    public function createTldParserByClass($className, $configType = null)
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
    public function getTldParserConfigByType($type)
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
     * @param array $configs
     * @param AsnParser $defaultParser
     * @return AsnServer[]
     */
    public function createAsnSevers($configs, AsnParser $defaultParser = null): array
    {
        $defaultParser = $defaultParser ?: AsnParser::create();
        $servers = [];
        foreach ($configs as $config) {
            $servers[] = $this->createAsnSever($config, $defaultParser);
        }
        return $servers;
    }

    /**
     * @param array $config
     * @param AsnParser $defaultParser
     * @return AsnServer
     */
    public function createAsnSever($config, AsnParser $defaultParser = null)
    {
        return new AsnServer(
            $config['host'] ?? '',
            $this->createAsnSeverParser($config, $defaultParser),
            $config['queryFormat'] ?? null
        );
    }

    /**
     * @param array $config
     * @param AsnParser|null $defaultParser
     * @return AsnParser
     */
    public function createAsnSeverParser(array $config, AsnParser $defaultParser = null): AsnParser
    {
        if (isset($config['parserClass'])) {
            return AsnParser::createByClass($config['parserClass']);
        }
        return $defaultParser ?: AsnParser::create();
    }

}
