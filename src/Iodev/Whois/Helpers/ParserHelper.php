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
     * @param string $header
     * @return array
     */
    public static function linesToGroups($lines, $header = '$header')
    {
        $groups = [];
        $group = [];
        $headerLines = [];
        $lines[] = '';
        foreach ($lines as $line) {
            $trimChars = " \t\n\r\0\x0B";
            $isComment = mb_strlen($line) != mb_strlen(ltrim($line, "%#;:"));
            $line = ltrim(rtrim($line, "%#*=$trimChars"), "%#*=;$trimChars");
            $headerLine = trim($line, ':[]');
            $headerLines[] = $headerLine;
            $kv = $isComment ? [] : explode(':', $line, 2);
            if (count($kv) == 2) {
                $k = trim($kv[0], ".:$trimChars");
                $v = trim($kv[1], ":$trimChars");
                $group = array_merge_recursive($group, [$k => ltrim($v, ".")]);
                continue;
            }
            if (empty($group[$header]) && count($group) > 0) {
                $group[$header] = self::linesToBestHeader($headerLines);
            }
            if (count($group) > 1) {
                $groups[] = array_filter($group);
                $group = [];
                $headerLines = [$headerLine];
            }
        }
        return $groups;
    }

    /**
     * @param string[] $lines
     * @return int|null|string
     */
    public static function linesToBestHeader($lines)
    {
        $map = [];
        $empty = 1;
        foreach ($lines as $line) {
            if (empty($line)) {
                $empty++;
                continue;
            }
            if ($empty > 0) {
                $empty = 0;
                $map[$line] = mb_strlen($line) + count(preg_split('~\s+~ui', $line));
            }
        }
        $header = '';
        if (!empty($map)) {
            asort($map, SORT_NUMERIC);
            $header = key($map);
        }
        return $header;
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

    /**
     * @param string[]|string $rawstates
     * @param bool $removeExtra
     * @return string[]
     */
    public static function parseStates($rawstates, $removeExtra = true)
    {
        $states = [];
        $rawstates = is_array($rawstates) ? $rawstates : [ strval($rawstates) ];
        foreach ($rawstates as $rawstate) {
            if (preg_match('/^\s*((\d{3}\s+)?[a-z]{2,}.*)\s*/ui', $rawstate, $m)) {
                $state = mb_strtolower($m[1]);
                $state = $removeExtra ? trim(preg_replace('~\(.+?\)|http.+~ui', '', $state)) : $state;
                if (!empty($state)) {
                    $states[] = $state;
                }
            }
        }
        return (count($states) == 1) ? array_filter(array_map('trim', explode(',', $states[0]))) : $states;
    }

    /**
     * @param string[] $lines
     * @return string[]
     */
    public static function autofixTldLines($lines)
    {
        $emptyBefore = false;
        $kvBefore = false;
        $needIndent = false;
        $outLines = [];
        foreach ($lines as $line) {
            if ($emptyBefore && preg_match('~^\w+(\s+\w+){0,2}$~', trim(rtrim($line, ':')))) {
                $line = trim(rtrim($line, ':')) . ':';
            }
            $isHeader = preg_match('~^\w+(\s+\w+){0,2}:$~', $line);
            if ($isHeader) {
                $outLines[] = '';
            }
            $needIndent = $needIndent || $isHeader;
            if (!empty($line) || !$kvBefore) {
                $indent = ($needIndent && !$isHeader && !empty($line)) ? '    ' : '';
                $outLines[] = $indent . $line;
            }
            $emptyBefore = empty($line);
            $kvBefore = preg_match('~^\w+(\s+\w+){0,2}:\s*\S+~', $line);
        }
        return $outLines;
    }
}
