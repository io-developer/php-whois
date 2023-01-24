<?php

declare(strict_types=1);

namespace Iodev\Whois;

use Iodev\Whois\Modules\Asn\AsnParser;
use Iodev\Whois\Modules\Asn\AsnServer;
use Iodev\Whois\Punycode\IPunycode;
use InvalidArgumentException;
use Iodev\Whois\Container\Default\ContainerBuilder;
use Psr\Container\ContainerInterface;

class Factory implements IFactory
{
    private ContainerInterface $container;

    public function __construct()
    {
        $this->container = (new ContainerBuilder())
            ->configure()
            ->getContainer()
        ;
    }

    public static function get(): Factory
    {
        static $instance;
        if (!$instance) {
            $instance = new static();
        }
        return $instance;
    }

    public function createPunycode(): IPunycode
    {
        return $this->container->get(IPunycode::class);
    }

    /**
     * @param array $configs|null
     * @param AsnParser $defaultParser
     * @return AsnServer[]
     */
    public function createAsnSevers($configs = null, AsnParser $defaultParser = null): array
    {
        $configs = is_array($configs) ? $configs : Config::load("module.asn.servers");
        $defaultParser = $defaultParser ?: $this->createAsnParser();
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
        $host = $config['host'] ?? '';
        if (empty($host)) {
            throw new InvalidArgumentException("Host must be specified");
        }
        return new AsnServer(
            $host,
            $this->createAsnSeverParser($config, $defaultParser),
            $config['queryFormat'] ?? AsnServer::DEFAULT_QUERY_FORMAT,
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
            return $this->createAsnParserByClass($config['parserClass']);
        }
        return $defaultParser ?: $this->createAsnParser();
    }

    /**
     * @return AsnParser
     */
    public function createAsnParser(): AsnParser
    {
        return new AsnParser();
    }

    /**
     * @param string $className
     * @return AsnParser
     */
    public function createAsnParserByClass($className): AsnParser
    {
        return new $className();
    }

}
