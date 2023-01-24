<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Tld;

use Iodev\Whois\Config;
use Iodev\Whois\Modules\Tld\Parsers\AutoParser;
use Iodev\Whois\Modules\Tld\Parsers\BlockParser;
use Iodev\Whois\Modules\Tld\Parsers\CommonParser;
use Iodev\Whois\Modules\Tld\Parsers\IndentParser;
use Psr\Container\ContainerInterface;

class TldParserProvider implements TldParserProviderInterface
{
    protected ContainerInterface $container;
    protected array $classByType;
    protected ?TldParser $default = null;
    protected array $cache = [];

    public function __construct(ContainerInterface $container)
    {
        $this->container = $container;
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
        $config = Config::load("module.tld.parser.$type") ?? [];
        return array_replace($config, $extra);
    }
}
