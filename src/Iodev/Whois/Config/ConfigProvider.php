<?php

declare(strict_types=1);

namespace Iodev\Whois\Config;

class ConfigProvider implements ConfigProviderInterface
{
    protected array $cache = [];

    public function __construct(
        protected string $baseDir = __DIR__.'/data',
    ) {}

    public function get(string $id): mixed
    {
        if (!isset($this->cache[$id])) {
            $this->cache[$id] = $this->load($id);
        }
        return $this->cache[$id];
    }

    protected function load(string $id): mixed
    {
        $path = $this->resolvePath($id, '.json');
        $json = file_get_contents($path);
        if ($json === false) {
            return false;
        }
        return json_decode($json, true);
    }

    protected function resolvePath(string $id, string $ext): string
    {
        return sprintf('%s/%s%s', $this->baseDir, $id, $ext);
    }
}
