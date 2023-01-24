<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Tld;

use InvalidArgumentException;
use Iodev\Whois\Config;

class TldServerProvider implements TldServerProviderInterface
{
    protected ?array $servers = null;

    public function __construct(
        protected TldParserProviderInterface $parserProvider,
    ) {}

    public function getList(): array
    {
        if ($this->servers === null) {
            $this->servers = [];

            $configs = Config::load("module.tld.servers");
            foreach ($configs as $config) {
                $this->servers[] = $this->create($config);
            }
        }
        return $this->servers;
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

        $type = $config['parserType'] ?? null;
        $className = $config['parserClass'] ?? null;
        if ($className) {
            $parser = $this->parserProvider->getByClassName($className, $type);
        } elseif ($type) {
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
