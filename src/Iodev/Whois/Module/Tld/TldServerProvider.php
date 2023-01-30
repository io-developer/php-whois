<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld;

use InvalidArgumentException;
use Iodev\Whois\Config\ConfigProviderInterface;

class TldServerProvider implements TldServerProviderInterface
{
    public const CONFIG_ID = 'module.tld.servers';
    public const DEFAULT_QUERY_FORMAT = "%s\r\n";

    protected TldServerCollection $collection;

    public function __construct(
        protected ConfigProviderInterface $configProvider,
        protected TldParserProviderInterface $parserProvider,
        protected TldServerMatcher $serverMatcher,
    ) {
        $this->collection = $this->createCollection();
    }

    protected function createCollection(): TldServerCollection
    {
        $col = new TldServerCollection();
        $configs = $this->configProvider->get(static::CONFIG_ID);
        foreach ($configs as $config) {
            $col->add($this->fromConfig($config));
        }
        return $col;
    }

    public function getCollection(): TldServerCollection
    {
        return $this->collection;
    }

    public function getMatched(string $domain): array
    {
        return $this->serverMatcher->match($this->collection->getList(), $domain);
    }

    public function fromConfig(array $config): TldServer
    {
        if (empty($config['zone'])) {
            throw new InvalidArgumentException('Zone must be specified');
        }
        if (empty($config['host'])) {
            throw new InvalidArgumentException('Host must be specified');
        }
        $parser = $this->getParser($config);

        return new TldServer(
            rtrim('.' . trim($config['zone'], '.'), '.'),
            $config['host'],
            $config['centralized'] ?? false,
            $parser,
            $config['queryFormat'] ?? static::DEFAULT_QUERY_FORMAT,
        );
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
