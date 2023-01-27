<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld;

use Iodev\Whois\Config\ConfigProviderInterface;
use Iodev\Whois\Module\Tld\Parser\AutoParser;
use Iodev\Whois\Module\Tld\Parser\BlockParser;
use Iodev\Whois\Module\Tld\Parser\CommonParser;
use Iodev\Whois\Module\Tld\Parser\IndentParser;
use Psr\Container\ContainerInterface;

class TldParserProvider implements TldParserProviderInterface
{
    protected ContainerInterface $container;
    protected ConfigProviderInterface $configProvider;
    protected array $classByType;
    protected ?TldParser $default = null;
    protected array $cache = [];

    public function __construct(ContainerInterface $container)
    {
        $this->container = $container;
        $this->configProvider = $container->get(ConfigProviderInterface::class);

        $this->classByType = [
            TldParser::AUTO => AutoParser::class,
            TldParser::COMMON => CommonParser::class,
            TldParser::COMMON_FLAT => CommonParser::class,
            TldParser::BLOCK => BlockParser::class,
            TldParser::INDENT => IndentParser::class,
            TldParser::INDENT_AUTOFIX => IndentParser::class,
        ];
    }

    public function getDefault(): TldParser
    {
        if ($this->default === null) {
            if ($this->container->has(TldParser::class)) {
                $this->default = $this->container->get(TldParser::class);
            } else {
                $this->default = $this->getByClassName(AutoParser::class);
            }
        }
        return $this->default;
    }

    public function getByType(string $type): TldParser
    {
        $className = $this->classByType[$type] ?? null;
        if (isset($this->classByType[$type])) {
            return $this->getByClassName($className, $type);
        }
        return $this->getDefault();
    }

    public function getByClassName(string $className, ?string $type = null): TldParser
    {
        $key = sprintf('%s:%s', $className, $type);
        if (empty($this->cache[$key])) {
            $this->cache[$key] = $this->create($className, $type);
        }
        return $this->cache[$key];
    }

    protected function create(string $className, ?string $type): TldParser
    {
        /** @var TldParser */
        $parser = $this->container->get($className);

        $type = $type ?: $parser->getType();

        $config = $this->getParserConfig($type);        
        $parser->setConfig($config);

        if ($className === AutoParser::class) {
            /** @var AutoParser */
            $autoParser = $parser;
            foreach ($config['parserTypes'] ?? [] as $parserType) {
                $autoParser->addParser($this->getByType($parserType));
            }
        }
        
        return $parser;
    }

    protected function getParserConfig(string $type): array
    {
        $extra = [];
        if ($type == TldParser::COMMON_FLAT) {
            $type = TldParser::COMMON;
            $extra = ['isFlat' => true];
        } elseif ($type == TldParser::INDENT_AUTOFIX) {
            $type = TldParser::INDENT;
            $extra = ['isAutofix' => true];
        }
        $config = $this->configProvider->get("module.tld.parser.$type") ?? [];
        return array_replace($config, $extra);
    }
}
