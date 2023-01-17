<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Asn;

use Iodev\Whois\Helpers\ParserHelper;

class AsnParser
{
    /**
     * @param AsnResponse $response
     * @return AsnInfo|null
     */
    public function parseResponse(AsnResponse $response)
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

    /**
     * @param string $content
     * @return array
     */
    protected function parseBlocks($content): array
    {
        return array_map([$this, 'parseBlock'], preg_split('~(\r\n|\r|\n){2,}~ui', $content));
    }

    /**
     * @param string $block
     * @return array
     */
    protected function parseBlock($block): array
    {
        $dict = [];
        foreach (ParserHelper::splitLines($block) as $line) {
            $kv = explode(':', $line, 2);
            if (count($kv) == 2) {
                list($k, $v) = $kv;
                $k = trim($k);
                $v = trim($v);
                $dict[$k] = empty($dict[$k]) ? $v : "{$dict[$k]}\n{$v}";
            }
        }
        return $dict;
    }

    /**
     * @param array $block
     * @return AsnRouteInfo
     */
    protected function createAsnRouteInfo(array $block): AsnRouteInfo
    {
        return new AsnRouteInfo($block);
    }

    /**
     * @param AsnResponse $response
     * @param AsnRouteInfo[] $routes
     * @return AsnInfo
     */
    protected function createAsnInfo(AsnResponse $response, array $routes): AsnInfo
    {
        return new AsnInfo($response, [
            'asn' => $response->asn,
            'routes' => $routes,
        ]);
    }
}
