<?php

declare(strict_types=1);

namespace Iodev\Whois\Helpers;

class GroupHelper
{
    /**
     * @param bool $ignoreCase
     * @return \Closure
     */
    public static function getMatcher($ignoreCase = true) {
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
     * @param bool $firstOnly
     * @param callable $matcher
     * @return string[]
     */
    public static function matchKeys($group, $keys, $firstOnly = false, $matcher = null)
    {
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
     * @param array $group
     * @param string[] $keys
     * @param array $outMatches
     * @param callable $matcher
     */
    private static function matchSubKeys($group, $keys, &$outMatches = [], $matcher = null)
    {
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

    /**
     * @param array $group
     * @param array $subset
     * @param callable $keyMatcher
     * @param callable $valMatcher
     * @return bool
     */
    public static function matchGroupSubset($group, $subset, $keyMatcher = null, $valMatcher = null)
    {
        $keyMatcher = is_callable($keyMatcher) ? $keyMatcher : self::getMatcher();
        $valMatcher = is_callable($valMatcher) ? $valMatcher : self::getMatcher();
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
            $foundDomain = null;
            foreach (self::matchKeys($group, $domainKeys, true) as $val) {
                $foundDomain = DomainHelper::toAscii($val);
                if (!empty($foundDomain)) {
                    break;
                }
            }
            if ($foundDomain && DomainHelper::compareNames($foundDomain, $domain)) {
                $foundGroups[] = $group;
                if ($stopOnFirst) {
                    break;
                }
            }
        }
        return $foundGroups;
    }
}
