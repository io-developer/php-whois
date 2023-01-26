<?php

declare(strict_types=1);

namespace Iodev\Whois\Tool;

class ParserTool
{
    /**
     * @return string[]
     */
    public function splitLines(string $text): array
    {
        return preg_split('~\r\n|\r|\n~ui', strval($text));
    }

    /**
     * @param string[] $lines
     */
    public function linesToGroups(array $lines, string $header = '$header'): array
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
            $kv = $isComment ? [] : $this->lineToKeyVal($line, ":$trimChars");
            if (count($kv) == 2) {
                $group = array_merge_recursive($group, [$kv[0] => ltrim($kv[1], ".")]);
                continue;
            }
            if (empty($group[$header]) && count($group) > 0) {
                $group[$header] = $this->linesToBestHeader($headerLines);
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
     * @return string[]
     */
    public function lineToKeyVal(string $line, string $trimChars = " \t\n\r\0\x0B"): array
    {
        if (preg_match('~^\s*(\.{2,})?\s*(.+?)\s*(\.{2,})?\s*:(?![\\/:])(?<!::)(.*)$~ui', $line, $m)) {
            return [trim($m[2], $trimChars), trim($m[4], $trimChars)];
        }
        return [trim($line, $trimChars)];
    }

    /**
     * @param string[] $lines
     * @return int|null|string
     */
    public function linesToBestHeader(array $lines): mixed
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
     */
    public function linesToSpacedBlocks(
        array $lines,
        callable $validateStoplineFn = null,
    ): array {
        $lines[] = '';
        $blocks = [];
        $block = [];
        foreach ($lines as $line) {
            $tline = trim($line);
            if (!empty($tline) && empty($block) && $validateStoplineFn !== null && !$validateStoplineFn($line)) {
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

    public function blockToIndentedNodes(
        array $block,
        ?callable $biasIndentFn = null,
        int $maxDepth = 10
    ): array {
        $nodes = [];
        $node = [];
        $nodePad = 999999;
        foreach ($block as $line) {
            $pad = $this->calcIndent($line, $biasIndentFn);
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
                $node['children'] = $this->blockToIndentedNodes($node['children'], null, $maxDepth - 1);
            }
            if (empty($node['children'])) {
                $node = $node['line'];
            }
        }
        return $nodes;
    }

    public function calcIndent(string $line, ?callable $biasFn = null): int
    {
        $pad = strlen($line) - strlen(ltrim($line));
        if ($biasFn !== null) {
            $pad += $biasFn($line);
        }
        return $pad;
    }

    public function nodesToDict(array $nodes, int $maxKeyLength = 32): array
    {
        $dict = [];
        foreach ($nodes as $node) {
            $node = is_array($node) ? $node : ['line' => $node, 'children' => []];
            $k = '';
            $v = '';
            $kv = $this->lineToKeyVal($node['line']);
            if (count($kv) == 2) {
                list ($k, $v) = $kv;
                if (empty($v)) {
                    $v = $this->nodesToDict($node['children']);
                } elseif (strlen($k) <= $maxKeyLength) {
                    $v = trim($v) ? [trim($v)] : [];
                    foreach ($node['children'] as $child) {
                        if (is_array($child)) {
                            $childV = $this->nodesToDict([$child]);
                            if (!empty($childV)) {
                                $dict = array_merge_recursive($dict, $childV);
                            }
                        } elseif (is_scalar($child)) {
                            $childV = trim((string)$child);
                            if (strlen($childV) > 0) {
                                $v[] = $childV;
                            }
                        }
                    }
                    $v = $v ?? [''];
                } else {
                    $kv = [$node['line']];
                }
            }
            if (count($kv) == 1) {
                $k = trim($kv[0]);
                $v = $this->nodesToDict($node['children']);
                if (empty($v)) {
                    $v = $k;
                    $k = '';
                }
            }
            if (!empty($k)) {
                $v = is_array($v)
                    ? (count($v) > 1 ? $v : reset($v))
                    : $v;
                $dict = array_merge_recursive($dict, [$k => $v]);
            } else {
                $dict[] = $v;
            }
        }
        return $dict;
    }

    public function dictToGroup(array $dict, string $header = '$header'): array
    {
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

    public function joinParentlessGroups(array $groups): array
    {
        $lastGroup = null;
        foreach ($groups as &$group) {
            if (count($group) == 1 && is_string(key($group)) && reset($group) === false) {
                $lastGroup = &$group;
                unset($group);
            } elseif (isset($lastGroup) && count($group) > 0 && is_string(key($group)) && reset($group)) {
                $lastGroup[key($lastGroup)] = $group;
                unset($lastGroup);
            }
        }
        unset($lastGroup);
        unset($group);
        return $groups;
    }

    /**
     * @param string[]|string $rawstates
     * @return string[]
     */
    public function parseStates(mixed $rawstates, bool $removeExtra = true): array
    {
        $states = [];
        $rawstates = is_array($rawstates) ? $rawstates : [ strval($rawstates) ];
        foreach ($rawstates as $rawstate) {
            if (preg_match('/^\s*((\d{3}\s+)?[a-z]{2,}.*)\s*/ui', $rawstate, $m)) {
                $state = mb_strtolower($m[1]);
                $state = $removeExtra ? trim(preg_replace('~\(.+?\)|((- )?http|<a href).+~ui', '', $state)) : $state;

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
    public function autofixTldLines(array $lines): array
    {
        $emptyBefore = false;
        $kvBefore = false;
        $needIndent = false;
        $outLines = [];
        foreach ($lines as $i => $line) {
            if ($emptyBefore && preg_match('~^\w+(\s+\w+){0,2}$~', trim(rtrim($line, ':')))) {
                $line = trim(rtrim($line, ':')) . ':';
            }
            // .jp style
            if (preg_match('~([a-z]\.)?\s*\[(.+?)\]\s+(.*)$~', $line, $m)) {
                $line = sprintf('%s: %s', $m[2], $m[3]);
            }
            $isHeader = preg_match('~^\w+(\s+\w+){0,2}:$~', $line);
            if ($isHeader) {
                $outLines[] = '';
            }
            $needIndent = $needIndent || $isHeader;
            if (!empty($line) || !$kvBefore) {
                if ($needIndent && !$isHeader && !empty($line)) {
                    $indent = '    ';
                    $nextLinePad = empty($lines[$i + 1]) || strlen(trim($lines[$i + 1])) == 0 ? 0 : $this->calcIndent($lines[$i + 1]);
                    if ($nextLinePad <= 2 && $this->calcIndent($lines[$i]) == 0) {
                        $indent .= str_repeat(' ', $nextLinePad);
                    }
                    $outLines[] = $indent . $line;
                } else {
                    $outLines[] = $line;
                }
            }
            $emptyBefore = empty($line);
            $kvBefore = preg_match('~^\w+(\s+\w+){0,2}:\s*\S+~', $line);
        }
        return $outLines;
    }

    /**
     * Removes unnecessary empty lines inside block
     * @param string[] $lines
     * @param callable|null $biasIndentFn
     * @return string[]
     */
    public function removeInnerEmpties(array $lines, callable $biasIndentFn = null): array
    {
        $prevPad = 0;
        $outLines = [];
        foreach ($lines as $index => $line) {
            if (empty($line)) {
                $nextLine = isset($lines[$index + 1]) ? $lines[$index + 1] : '';
                if (!empty($nextLine) && $prevPad > 0 && $prevPad == $this->calcIndent($nextLine, $biasIndentFn)) {
                    continue;
                }
            }
            $prevPad = empty($line) ? 0 : $this->calcIndent($line, $biasIndentFn);
            $outLines[] = $line;
        }
        return $outLines;
    }
}
