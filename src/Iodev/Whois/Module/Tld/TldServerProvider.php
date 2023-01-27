<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld;

use InvalidArgumentException;
use Iodev\Whois\Config\ConfigProviderInterface;
use Psr\Container\ContainerInterface;

class TldServerProvider implements TldServerProviderInterface
{
    protected ConfigProviderInterface $configProvider;
    protected ?array $servers = null;

    public function __construct(
        protected ContainerInterface $container,
        protected TldParserProviderInterface $parserProvider,
    ) {
        $this->configProvider = $container->get(ConfigProviderInterface::class);
    }

    public function getList(): array
    {
        if ($this->servers === null) {
            $this->servers = [];

            $configs = $this->configProvider->get("module.tld.servers");
            foreach ($configs as $config) {
                $this->servers[] = $this->create($config);
            }
        }
        return $this->servers;
    }

    public function getCollection(): TldServerCollection
    {
        $col = new TldServerCollection();
        $col->setList($this->getList());
        return $col;
    }

    public function create(array $config): TldServer
    {
        if (empty($config['zone'])) {
            throw new InvalidArgumentException("Zone must be specified");
        }
        if (empty($config['host'])) {
            throw new InvalidArgumentException("Host must be specified");
        }
        $parser = $this->getParser($config);

        return new TldServer(
            rtrim('.' . trim($config['zone'], '.'), '.'),
            $config['host'],
            $config['centralized'] ?? false,
            $parser,
            $config['queryFormat'] ?? TldServer::DEFAULT_QUERY_FORMAT,
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

    protected function getParser(array $config): TldParser
    {
        $options = $config['parserOptions'] ?? [];

        $parser = $config['parser'] ?? null;
        $type = $config['parserType'] ?? null;
        $className = $config['parserClass'] ?? null;
        if ($parser !== null && $parser instanceof TldParser) {
            // do nothing
        } elseif (!empty($className) && class_exists($className)) {
            $parser = $this->parserProvider->getByClassName($className, $type);
        } elseif (!empty($type)) {
            $parser = $this->parserProvider->getByType($type);
        } else {
            $parser = $this->parserProvider->getDefault();
        }

        if (is_array($options) && count($options) > 0) {
            $parser = clone $parser;
            $parser->setOptions($options);
        }

        return $parser;
    }
}
