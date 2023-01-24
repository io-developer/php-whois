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
            $this->default = $this->getByClassName(AutoParser::class, TldParser::AUTO);
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
        $config = $type ? $this->getParserConfig($type) : [];

        $parser = $this->container->get($className);
        $parser->setConfig($config);

        if ($className === AutoParser::class || $type === TldParser::AUTO) {
            foreach ($config['parserTypes'] ?? [] as $type) {
                $parser->addParser($this->getByType($type));
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
