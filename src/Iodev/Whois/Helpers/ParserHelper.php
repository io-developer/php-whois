<?php

namespace Iodev\Whois\Helpers;

class ParserHelper
{
    /**
     * @param string $text
     * @return string[]
     */
    public static function splitLines($text)
    {
        return preg_split('~\r\n|\r|\n~ui', strval($text));
    }

    /**
     * @param string[] $lines
     * @param callable $validateStoplineFn
     * @return array
     */
    public static function linesToSpacedBlocks($lines, $validateStoplineFn = null)
    {
        $lines[] = '';
        $blocks = [];
        $block = [];
        foreach ($lines as $line) {
            $tline = trim($line);
            if (!empty($tline) && empty($block) && is_callable($validateStoplineFn) && !$validateStoplineFn($line)) {
                break;
            } elseif (!empty($tline)) {
                $block[] = $line;
            } elseif (!empty($block)) {
                $blocks[] = $block;
                $block = [];
            }
        }
        return $blocks;
    }

    /**
     * @param array $block
     * @param callable $biasIndentFn
     * @param int $maxDepth
     * @return array
     */
    public static function blockToIndentedNodes($block, $biasIndentFn = null, $maxDepth = 10)
    {
        $nodes = [];
        $node = [];
        $nodePad = 999999;
        foreach ($block as $line) {
            $pad = self::calcIndent($line, $biasIndentFn);
            if ($pad <= $nodePad) {
                $nodePad = $pad;
                $nodes[] = [
                    'line' => $line,
                    'children' => [],
                ];
                $node = &$nodes[count($nodes) - 1];
            } else {
                $node['children'][] = $line;
            }
        }
        unset($node);
        foreach ($nodes as &$node) {
            if (!empty($node['children']) && $maxDepth > 1) {
                $node['children'] = self::blockToIndentedNodes($node['children'], $maxDepth - 1);
            }
            if (empty($node['children'])) {
                $node = $node['line'];
            }
        }
        return $nodes;
    }

    /**
     * @param string $line
     * @param callable $biasFn
     * @return int
     */
    public static function calcIndent($line, $biasFn = null)
    {
        $pad = strlen($line) - strlen(ltrim($line));
        if (is_callable($biasFn)) {
            $pad += $biasFn($line);
        }
        return $pad;
    }

    /**
     * @param array $nodes
     * @param int $maxKeyLength
     * @return array
     */
    public static function nodesToDict($nodes, $maxKeyLength = 32)
    {
        $dict = [];
        foreach ($nodes as $node) {
            $node = is_array($node) ? $node : ['line' => $node, 'children' => []];
            $k = '';
            $v = '';
            $kv = explode(':', $node['line'], 2);
            if (count($kv) == 2) {
                $k = trim($kv[0]);
                $v = trim($kv[1]);
                if (empty($v)) {
                    $v = self::nodesToDict($node['children']);
                } elseif (strlen($k) <= $maxKeyLength) {
                    $v = array_merge([$v], $node['children']);
                    $v = array_map('trim', $v);
                    $v = array_filter($v, 'strlen');
                    $v = empty($v) ? [''] : $v;
                } else {
                    $kv = [$node['line']];
                }
            }
            if (count($kv) == 1) {
                $k = trim($kv[0]);
                $v = self::nodesToDict($node['children']);
                if (empty($v)) {
                    $v = $k;
                    $k = '';
                }
            }
            if (!empty($k)) {
                $dict[$k] = is_array($v)
                    ? (count($v) > 1 ? $v : reset($v))
                    : $v;
            } else {
                $dict[] = $v;
            }
        }
        return $dict;
    }

    /**
     * @param array $dict
     * @param string $header
     * @return array
     */
    public static function dictToGroup($dict, $header = '$header') {
        if (empty($dict) || count($dict) > 1) {
            return $dict;
        }
        $k = array_keys($dict)[0];
        $v = array_values($dict)[0];
        if (!is_string($k) || !is_array($v)) {
            return $dict;
        }
        $vk = array_keys($v)[0];
        if (is_string($vk)) {
            return array_merge([$header => $k], $v);
        }
        $dict[$header] = $k;
        return $dict;
    }
}
