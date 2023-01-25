<?php

declare(strict_types=1);

namespace Iodev\Whois\Helpers;

use Iodev\Whois\Tool\DomainTool;

class GroupHelper
{
    public static function getMatcher(bool $ignoreCase = true): callable
    {
        return function($needle, $subject) use ($ignoreCase) {
            $needle = (string)$needle;
            $subject = (string)$subject;
            if ($needle === $subject) {
                return true;
            }
            if (strlen($needle) > 1 && $needle[0] === '~') {
                return (bool)preg_match($needle, $subject);
            }
            return $ignoreCase && mb_strtolower($needle) === mb_strtolower($subject);
        };
    }

    public static function toLowerCase(array $group, bool $keysOnly = false): array
    {
        return $keysOnly
            ? self::mapRecursiveKeys($group, 'mb_strtolower')
            : self::mapRecursive($group, 'mb_strtolower');
    }

    public static function mapRecursive(array $group, callable $callback): array
    {
        $out = [];
        array_walk($group, function($val, $key) use (&$out, $callback) {
            $out[$callback($key)] = is_array($val) ? self::mapRecursive($val, $callback) : $callback($val);
        });
        return $out;
    }

    public static function mapRecursiveKeys(array $group, callable $callback): array
    {
        $out = [];
        array_walk($group, function($val, $key) use (&$out, $callback) {
            $out[$callback($key)] = is_array($val) ? self::mapRecursiveKeys($val, $callback) : $val;
        });
        return $out;
    }

    /**
     * @param string[] $keys
     * @return string[]
     */
    public static function matchKeys(
        array $group,
        array $keys,
        bool $firstOnly = false,
        callable $matcher = null,
    ): array {
        if (empty($group)) {
            return [];
        }
        $matcher = is_callable($matcher) ? $matcher : self::getMatcher();
        $matches = [];
        foreach ($keys as $key) {
            if (is_array($key)) {
                self::matchSubKeys($group, $key, $matches);
            } elseif (isset($group[$key])) {
                $matches[] = $group[$key];
            } else {
                foreach ($group as $groupKey => $groupVal) {
                    if ($matcher($key, $groupKey)) {
                        $matches[] = $groupVal;
                        if ($firstOnly) {
                            break;
                        }
                    }
                }
            }
            if ($firstOnly && count($matches) > 0) {
                break;
            }
        }
        return $matches;
    }

    /**
     * @param string[] $keys
     */
    private static function matchSubKeys(
        array $group,
        array $keys,
        array &$outMatches = [],
        callable $matcher = null,
    ): void {
        $vals = [];
        foreach ($keys as $k) {
            $v = self::matchKeys($group, [$k], true, $matcher);
            $v = empty($v) ? "" : reset($v);
            if (is_array($v)) {
                $vals = array_merge($vals, $v);
            } elseif (!empty($v)) {
                $vals[] = $v;
            }
        }
        if (count($vals) > 1) {
            $outMatches[] = $vals;
        } elseif (count($vals) == 1) {
            $outMatches[] = $vals[0];
        } else {
            $outMatches[] = "";
        }
    }

    public static function renderSubsets(array $subsets, array $params): array
    {
        array_walk_recursive($subsets, function(&$val) use ($params) {
            $origVal = (string)$val;
            $val = preg_replace_callback('~\\$[a-z][a-z\d]*\b~ui', function($m) use ($origVal, $params) {
                $arg = $m[0];
                $newVal = isset($params[$arg]) ? $params[$arg] : $arg;
                if (strlen($origVal) > 1 && $origVal[0] == '~') {
                    $newVal = preg_quote($newVal);
                }
                return $newVal;
            }, $val);
        });
        return $subsets;
    }

    public static function findGroupsHasSubsetOf(
        array $groups,
        array $subsets,
        bool $ignoreCase = true,
        bool $stopOnFirst = false,
    ): array {
        $keyMatcher = self::getMatcher($ignoreCase);
        $valMatcher = self::getMatcher($ignoreCase);
        $foundGroups = [];
        foreach ($subsets as $subset) {
            foreach ($groups as $group) {
                if (self::matchGroupSubset($group, $subset, $keyMatcher, $valMatcher)) {
                    $foundGroups[] = $group;
                    if ($stopOnFirst) {
                        break;
                    }
                }
            }
        }
        return $foundGroups;
    }

    public static function matchGroupSubset(
        array $group,
        array $subset,
        callable $keyMatcher = null,
        callable $valMatcher = null
    ): bool {
        $keyMatcher = $keyMatcher ?: self::getMatcher();
        $valMatcher = $valMatcher ?: self::getMatcher();
        foreach ($subset as $subsetKey => $subsetVal) {
            $isKeyMatched = false;
            $groupVal = null;
            if (isset($group[$subsetKey])) {
                $isKeyMatched = true;
                $groupVal = $group[$subsetKey];
            } else {
                foreach ($group as $groupKey => $gv) {
                    $isKeyMatched = $keyMatcher($subsetKey, $groupKey);
                    if ($isKeyMatched) {
                        $groupVal = $gv;
                        break;
                    }
                }
            }
            if (!$isKeyMatched) {
                return false;
            }
            if (empty($subsetVal)) {
                continue;
            }
            if (is_array($groupVal)) {
                foreach ($groupVal as $groupSubVal) {
                    if ($valMatcher($subsetVal, $groupSubVal)) {
                        $found = true;
                        break;
                    }
                }
            } else {
                $found = $valMatcher($subsetVal, $groupVal);
            }
            if (empty($found)) {
                return false;
            }
        }
        return true;
    }

    public static function findDomainGroups(
        array $groups,
        string $domain,
        array $domainKeys,
        bool $stopOnFirst,
        DomainTool $domainTool,
    ): array {
        $foundGroups = [];
        foreach ($groups as $group) {
            $foundDomain = null;
            foreach (self::matchKeys($group, $domainKeys, true) as $val) {
                $foundDomain = $domainTool->toAscii($val);
                if (!empty($foundDomain)) {
                    break;
                }
            }
            if ($foundDomain && $domainTool->isEqual($foundDomain, $domain)) {
                $foundGroups[] = $group;
                if ($stopOnFirst) {
                    break;
                }
            }
        }
        return $foundGroups;
    }
}
