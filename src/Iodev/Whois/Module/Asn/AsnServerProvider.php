<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Asn;

use InvalidArgumentException;
use Iodev\Whois\Config\ConfigProviderInterface;
use Psr\Container\ContainerInterface;

class AsnServerProvider implements AsnServerProviderInterface
{
    protected ?array $servers = null;

    public function __construct(
        protected ContainerInterface $container,
    ) {}

    public function getList(): array
    {
        if ($this->servers === null) {
            $this->servers = [];

            /** @var ConfigProviderInterface */
            $configProvider = $this->container->get(ConfigProviderInterface::class);

            $configs = $configProvider->get('module.asn.servers');
            foreach ($configs as $config) {
                $this->servers[] = $this->create($config);
            }
        }
        return $this->servers;
    }

    public function create(array $config): AsnServer
    {
        $host = $config['host'] ?? '';
        if (empty($host)) {
            throw new InvalidArgumentException("Host must be specified");
        }
        return new AsnServer(
            $host,
            $this->getParser($config),
            $config['queryFormat'] ?? AsnServer::DEFAULT_QUERY_FORMAT,
        );
    }

    public function createMany(array $configList): array
    {
        $servers = [];
        foreach ($configList as $config) {
            $servers[] = $this->create($config);
        }
        return $servers;
    }

    protected function getParser(array $config): AsnParser
    {
        $className = $config['parserClass'] ?? AsnParser::class;
        return $this->container->get($className);
    }
}
