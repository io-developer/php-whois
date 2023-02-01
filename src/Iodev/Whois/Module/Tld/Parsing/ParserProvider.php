<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\Parsing;

use Iodev\Whois\Config\ConfigProviderInterface;
use Iodev\Whois\Module\Tld\Parsing\AutoParser;
use Iodev\Whois\Module\Tld\Parsing\BlockParser;
use Iodev\Whois\Module\Tld\Parsing\CommonParser;
use Iodev\Whois\Module\Tld\Parsing\IndentParser;
use Psr\Container\ContainerInterface;

class ParserProvider implements ParserProviderInterface
{
    protected ContainerInterface $container;
    protected ConfigProviderInterface $configProvider;
    protected array $classByType;
    protected ?ParserInterface $default = null;
    protected array $cache = [];

    public function __construct(ContainerInterface $container)
    {
        $this->container = $container;
        $this->configProvider = $container->get(ConfigProviderInterface::class);

        $this->classByType = [
            ParserInterface::AUTO => AutoParser::class,
            ParserInterface::COMMON => CommonParser::class,
            ParserInterface::COMMON_FLAT => CommonParser::class,
            ParserInterface::BLOCK => BlockParser::class,
            ParserInterface::INDENT => IndentParser::class,
            ParserInterface::INDENT_AUTOFIX => IndentParser::class,
        ];
    }

    public function getDefault(): ParserInterface
    {
        if ($this->default === null) {
            if ($this->container->has(ParserInterface::class)) {
                $this->default = $this->container->get(ParserInterface::class);
            } else {
                $this->default = $this->getByClassName(AutoParser::class);
            }
        }
        return $this->default;
    }

    public function getByType(string $type): ParserInterface
    {
        $className = $this->classByType[$type] ?? null;
        if (isset($this->classByType[$type])) {
            return $this->getByClassName($className, $type);
        }
        return $this->getDefault();
    }

    public function getByClassName(string $className, ?string $type = null): ParserInterface
    {
        $key = sprintf('%s:%s', $className, $type);
        if (empty($this->cache[$key])) {
            $this->cache[$key] = $this->create($className, $type);
        }
        return $this->cache[$key];
    }

    protected function create(string $className, ?string $type): ParserInterface
    {
        /** @var ParserInterface */
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
        if ($type == ParserInterface::COMMON_FLAT) {
            $type = ParserInterface::COMMON;
            $extra = ['isFlat' => true];
        } elseif ($type == ParserInterface::INDENT_AUTOFIX) {
            $type = ParserInterface::INDENT;
            $extra = ['isAutofix' => true];
        }
        $config = $this->configProvider->get("module.tld.parser.$type") ?? [];
        return array_replace($config, $extra);
    }
}
