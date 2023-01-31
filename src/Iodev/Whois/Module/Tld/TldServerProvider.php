<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld;

use InvalidArgumentException;
use Iodev\Whois\Config\ConfigProviderInterface;
use Iodev\Whois\Loader\LoaderInterface;
use Psr\Container\ContainerInterface;

class TldServerProvider implements TldServerProviderInterface
{
    public const CONFIG_ID = 'module.tld.servers';
    public const DEFAULT_QUERY_FORMAT = "%s\r\n";
    public const DEFAULT_PRIORITY = 0;
    public const UPDATED_WHOIS_PRIORITY = 127;

    protected TldServerCollection $collection;
    protected bool $whoisUpdateEnabled = true;

    public function __construct(
        protected ContainerInterface $container,
        protected ConfigProviderInterface $configProvider,
        protected LoaderInterface $loader,
        protected TldParserProviderInterface $parserProvider,
        protected TldServerMatcher $serverMatcher,
    ) {
        $this->collection = $this->createCollection();
    }

    public function getWhoisUpdateEnabled(): bool
    {
        return $this->whoisUpdateEnabled;
    }

    public function setWhoisUpdateEnabled(bool $enabled): static
    {
        $this->whoisUpdateEnabled = $enabled;
        return $this;
    }

    public function getCollection(): TldServerCollection
    {
        return $this->collection;
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

    public function getMatched(string $domain): array
    {
        $collectionUpdated = false;

        $servers = $this->serverMatcher->match($this->collection->getList(), $domain);

        if (count($servers) === 0) {
            $collectionUpdated = $this->updateCollectionFor($domain, null);
        } else {
            $firstServer = $servers[0];
            $isSimpleZone = count($firstServer->getInverseZoneParts()) == 1;
            if ($isSimpleZone && $firstServer->priority < static::UPDATED_WHOIS_PRIORITY) {
                $collectionUpdated = $this->updateCollectionFor($domain, $firstServer);
            }
        }

        if ($collectionUpdated) {
            $servers = $this->serverMatcher->match($this->collection->getList(), $domain);
        }

        return $servers;
    }

    protected function updateCollectionFor(string $domain, ?TldServer $server): bool
    {
        if (!$this->whoisUpdateEnabled) {
            return false;
        }

        $queryDomain = $domain;
        if ($server !== null) {
            $queryDomain = trim($server->zone, '.');
        }
        if (empty($queryDomain)) {
            return false;
        }

        /** @var TldLookupWhoisCommand */
        $command = $this->container->get(TldLookupWhoisCommand::class);
        $command
            ->setLoader($this->loader)
            ->setDomain($queryDomain)
            ->execute()
        ;
        $result = $command->getResult();

        $resultZone = $result->info?->domainName ?? null;
        $resultWhoisHost = $result->info?->whoisServer ?? null;

        if (empty($resultZone) || empty($resultWhoisHost)) {
            return false;
        }

        $ianaServer = $this->fromConfig([
            'zone' => $resultZone,
            'host' => $resultWhoisHost,
            'centralized' => $server ? $server->centralized : false,
            'parser' => $server ? $server->parser : null,
            'queryFormat' => $server ? $server->queryFormat : null,
            'priority' => static::UPDATED_WHOIS_PRIORITY,
        ]);

        $this->collection->add($ianaServer);

        return true;
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
            rtrim('.' . trim(mb_strtolower($config['zone']), '.'), '.'),
            $config['host'],
            $config['centralized'] ?? false,
            $parser,
            $config['queryFormat'] ?? static::DEFAULT_QUERY_FORMAT,
            $config['priority'] ?? static::DEFAULT_PRIORITY,
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
