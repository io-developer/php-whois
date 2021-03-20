<?php

namespace Iodev\Whois\Helpers;

class GroupHelper
{
    /**
     * @param array $group
     * @param bool $keysOnly
     * @return array
     */
    public static function toLowerCase($group, $keysOnly = false)
    {
        return $keysOnly
            ? self::mapRecursiveKeys($group, 'mb_strtolower')
            : self::mapRecursive($group, 'mb_strtolower');
    }

    /**
     * @param array $group
     * @param callable $callback
     * @return array
     */
    public static function mapRecursive($group, $callback) {
        $out = [];
        array_walk($group, function($val, $key) use (&$out, $callback) {
            $out[$callback($key)] = is_array($val) ? self::mapRecursive($val, $callback) : $callback($val);
        });
        return $out;
    }

    /**
     * @param array $group
     * @param callable $callback
     * @return array
     */
    public static function mapRecursiveKeys($group, $callback) {
        $out = [];
        array_walk($group, function($val, $key) use (&$out, $callback) {
            $out[$callback($key)] = is_array($val) ? self::mapRecursiveKeys($val, $callback) : $val;
        });
        return $out;
    }

    /**
     * @param array $group
     * @param string[] $keys
     * @param bool $ignoreCase
     * @return string|string[]
     */
    public static function matchFirst($group, $keys, $ignoreCase = true)
    {
        $matches = self::match($group, $keys, $ignoreCase, true);
        return empty($matches) ? "" : reset($matches);
    }

    /**
     * @param array $group
     * @param string[] $keys
     * @param bool $ignoreCase
     * @param bool $firstOnly
     * @return string|string[]
     */
    public static function match($group, $keys, $ignoreCase = true, $firstOnly = false)
    {
        $matches = [];
        if (empty($group)) {
            return [];
        }
        if ($ignoreCase) {
            $group = self::toLowerCase($group, true);
        }
        foreach ($keys as $k) {
            if (is_array($k)) {
                $vals = self::matchAll($group, $k, $ignoreCase);
                if (count($vals) > 1) {
                    $matches[] = $vals;
                } elseif (count($vals) == 1) {
                    $matches[] = $vals[0];
                } else {
                    $matches[] = "";
                }
            } else {
                $k = $ignoreCase ? mb_strtolower($k) : $k;
                if (isset($group[$k])) {
                    $matches[] = $group[$k];
                }
            }
            if ($firstOnly && count($matches) > 0) {
                return $matches;
            }
        }
        return $matches;
    }

    /**
     * @param array $group
     * @param string[] $keys
     * @param bool $ignoreCase
     * @return string[]
     */
    private static function matchAll($group, $keys, $ignoreCase = true)
    {
        $vals = [];
        foreach ($keys as $k) {
            $v = self::matchFirst($group, [$k], $ignoreCase);
            if (is_array($v)) {
                $vals = array_merge($vals, $v);
            } elseif (!empty($v)) {
                $vals[] = $v;
            }
        }
        return $vals;
    }

    /**
     * @param array $subsets
     * @param array $params
     * @return array
     */
    public static function renderSubsets($subsets, $params)
    {
        array_walk_recursive($subsets, function(&$val) use ($params) {
            $val = preg_replace_callback('~\\$[a-z][a-z\d]*\b~ui', function($m) use ($params) {
                $arg = $m[0];
                return isset($params[$arg]) ? $params[$arg] : $arg;
            }, $val);
        });
        return $subsets;
    }

    /**
     * @param array $groups
     * @param array $subsets
     * @param bool $ignoreCase
     * @param bool $stopnOnFirst
     * @return array
     */
    public static function findGroupsHasSubsetOf($groups, $subsets, $ignoreCase = true, $stopnOnFirst = false)
    {
        $preparedGroups = $groups;
        $preparedSubsets = $subsets;
        if ($ignoreCase) {
            foreach ($groups as $groupKey => $group) {
                $preparedGroups[$groupKey] = self::toLowerCase($group);
            }
            $preparedSubsets = self::toLowerCase($subsets);
        }
        $foundGroups = [];
        foreach ($preparedSubsets as $preparedSubset) {
            foreach ($preparedGroups as $groupKey => $preparedGroup) {
                if (self::hasSubset($preparedGroup, $preparedSubset)) {
                    $foundGroups[] = $groups[$groupKey];
                    if ($stopnOnFirst) {
                        break;
                    }
                }
            }
        }
        return $foundGroups;
    }

    /**
     * @param array $group
     * @param array $subset
     * @return bool
     */
    public static function hasSubset($group, $subset)
    {
        foreach ($subset as $k => $v) {
            if (!isset($group[$k])) {
                return false;
            }
            if (empty($v)) {
                continue;
            }
            if (is_array($group[$k])) {
                foreach ($group[$k] as $groupSubval) {
                    if (self::matchSubsetVal($groupSubval, $v)) {
                        $found = true;
                    }
                }
            } else {
                $found = self::matchSubsetVal($group[$k], $v);
            }
            if (empty($found)) {
                 return false;
            }
        }
        return true;
    }

    /**
     * @param $groupVal
     * @param $subsetVal
     * @return bool
     */
    private static function matchSubsetVal($groupVal, $subsetVal)
    {
        $haystack = (string)$groupVal;
        $needle = (string)$subsetVal;
        if (strlen($needle) > 1 && $needle[0] === '~') {
            $re = $needle;
            $subj = (string)$groupVal;
            $res = preg_match($re, $subj);
            return (bool)$res;
        }
        return $haystack === $needle;
    }

    /**
     * @param array $groups
     * @param string $domain
     * @param string[] $domainKeys
     * @param bool $stopOnFirst
     * @return array
     */
    public static function findDomainGroups($groups, $domain, $domainKeys, $stopOnFirst = false)
    {
        $foundGroups = [];
        foreach ($groups as $group) {
            $foundDomain = self::getAsciiServer($group, $domainKeys);
            if ($foundDomain && DomainHelper::compareNames($foundDomain, $domain)) {
                $foundGroups[] = $group;
                if ($stopOnFirst) {
                    break;
                }
            }
        }
        return $foundGroups;
    }

    /**
     * @param array $group
     * @param string[] $keys
     * @return string
     */
    public static function getAsciiServer($group, $keys)
    {
        $servers = self::getAsciiServers($group, $keys);
        return empty($servers) ? "" : $servers[0];
    }

    /**
     * @param array $group
     * @param string[] $keys
     * @return string[]
     */
    public static function getAsciiServers($group, $keys)
    {
        $raws = self::matchFirst($group, $keys);
        $raws = !empty($raws) ? $raws : [];
        $raws = is_array($raws) ? $raws : [ $raws ];
        $servers = [];
        foreach ($raws as $raw) {
            $s = DomainHelper::toAscii($raw);
            if (!empty($s)) {
                $servers[] = $s;
            }
        }
        return $servers;
    }
}
