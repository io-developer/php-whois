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

    /**
     * @param array $groups
     * @param array $subsets
     * @param bool $ignoreCase
     * @param bool $stopOnFirst
     * @return array
     */
    public static function findGroupsHasSubsetOf($groups, $subsets, $ignoreCase = true, $stopOnFirst = false)
    {
        $keyMatcher = function($needle, $subject) use ($ignoreCase) {
            if ($needle === $subject) {
                return true;
            }
            if (strlen($needle) > 1 && (string)$needle[0] === '~') {
                return (bool)preg_match((string)$needle, $subject);
            }
            if ($ignoreCase) {
                return mb_strtolower($needle) === mb_strtolower($subject);
            }
            return false;
        };
        $valMatcher = function($needle, $subject) use ($ignoreCase) {
            if ($needle === $subject) {
                return true;
            }
            $subject = (string)$subject;
            $needle = (string)$needle;
            if ($needle === $subject) {
                return true;
            }
            if (strlen($needle) > 1 && $needle[0] === '~') {
                $res = preg_match($needle, $subject);
                return (bool)$res;
            }
            if ($ignoreCase) {
                return mb_strtolower($needle) === mb_strtolower($subject);
            }
            return false;
        };
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

    /**
     * @param array $group
     * @param array $subset
     * @param callable $keyMatcher
     * @param callable $valMatcher
     * @return bool
     */
    public static function matchGroupSubset($group, $subset, $keyMatcher = null, $valMatcher = null)
    {
        $keyMatcher = is_callable($keyMatcher) ? $keyMatcher : function($needle, $subject) {
            return $needle === $subject;
        };
        $valMatcher = is_callable($valMatcher) ? $valMatcher : function($needle, $subject) {
            return $needle == $subject;
        };
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
