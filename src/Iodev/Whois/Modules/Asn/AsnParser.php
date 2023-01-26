<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Asn;

use Iodev\Whois\Tool\ParserTool;

class AsnParser
{
    public function __construct(
        protected ParserTool $parserTool,
    ) {}

    public function parseResponse(AsnResponse $response): ?AsnInfo
    {
        $routes = [];
        foreach ($this->parseBlocks($response->text) as $block) {
            if (count($block) > 1) {
                $routes[] = $this->createAsnRouteInfo($block);
            }
        }
        if (count($routes) == 0) {
            return null;
        }
        return $this->createAsnInfo($response, $routes);
    }

    protected function parseBlocks(string $content): array
    {
        return array_map(
            fn ($item) => $this->parseBlock($item),
            preg_split('~(\r\n|\r|\n){2,}~ui', $content),
        );
    }

    protected function parseBlock(string $block): array
    {
        $dict = [];
        foreach ($this->parserTool->splitLines($block) as $line) {
            $kv = explode(':', $line, 2);
            if (count($kv) == 2) {
                [$k, $v] = $kv;
                $k = trim($k);
                $v = trim($v);
                $dict[$k] = empty($dict[$k]) ? $v : "{$dict[$k]}\n{$v}";
            }
        }
        return $dict;
    }

    protected function createAsnRouteInfo(array $data): AsnRouteInfo
    {
        return new AsnRouteInfo(
            $data['route'] ?? '',
            $data['route6'] ?? '',
            $data['descr'] ?? '',
            $data['origin'] ?? '',
            $data['mnt-by'] ?? '',
            $data['changed'] ?? '',
            $data['source'] ?? '',
        );
    }

    protected function createAsnInfo(AsnResponse $response, array $routes): AsnInfo
    {
        return new AsnInfo(
            $response, 
            $response->asn,
            $routes,
        );
    }
}
