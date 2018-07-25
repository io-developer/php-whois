<?php

namespace Iodev\Whois\Helpers;

class GroupFilter
{
    /**
     * @param array $groups
     * @return GroupFilter
     */
    public static function create($groups = [])
    {
        $m = new self();
        $m->setGroups($groups);
        return $m;
    }

    public function __construct()
    {
    }

    /** @var array */
    private $groups = [];

    /** @var string */
    private $headerKey = '$header';

    /** @var array */
    private $domainKeys = [];

    /** @var array */
    private $subsetParams = [];

    /**
     * @return GroupFilter
     */
    public function cloneMe()
    {
        return clone $this;
    }

    /**
     * @return array
     */
    public function getFirstGroup()
    {
        return count($this->groups) ? $this->groups[0] : null;
    }

    /**
     * @return array
     */
    public function getGroups()
    {
        return $this->groups;
    }

    /**
     * @param array $groups
     * @return $this
     */
    public function setGroups($groups)
    {
        $this->groups = $groups;
        return $this;
    }

    /**
     * @param array $group
     * @return $this
     */
    public function setOneGroup($group)
    {
        $this->groups = $group ? [ $group ] : [];
        return $this;
    }

    /**
     * @return $this
     */
    public function useFirstGroup()
    {
        return $this->setOneGroup($this->getFirstGroup());
    }

    /**
     * @param array $group
     * @return $this
     */
    public function useFirstGroupOr($group)
    {
        $first = $this->getFirstGroup();
        return $this->setOneGroup(empty($first) ? $group : $first);
    }

    /**
     * @param string $key
     * @return $this
     */
    public function setHeaderKey($key)
    {
        $this->headerKey = $key;
        return $this;
    }

    /**
     * @param array $keys
     * @return $this
     */
    public function setDomainKeys($keys)
    {
        $this->domainKeys = $keys;
        return $this;
    }

    /**
     * @param array $params
     * @return $this
     */
    public function setSubsetParams($params)
    {
        $this->subsetParams = $params;
        return $this;
    }

    /**
     * @return $this
     */
    public function mergeGroups()
    {
        $finalGroup = [];
        foreach ($this->groups as $group) {
            $finalGroup = array_merge_recursive($finalGroup, $group);
        }
        $this->groups = [ $finalGroup ];
        return $this;
    }

    /**
     * @param string $domain
     * @param bool $matchFirst
     * @return GroupFilter
     */
    public function filterIsDomain($domain, $matchFirst = false)
    {
        $groups = GroupHelper::findDomainGroups($this->groups, $domain, $this->domainKeys, $matchFirst);
        return $this->cloneMe()->setGroups($groups);
    }

    /**
     * @param array $subsets
     * @param bool $matchFirst
     * @return $this
     */
    public function filterHasSubsetOf($subsets, $matchFirst = false)
    {
        $subsets = GroupHelper::renderSubsets($subsets, $this->subsetParams);
        $groups = GroupHelper::findGroupsHasSubsetOf($this->groups, $subsets, true, $matchFirst);
        return $this->cloneMe()->setGroups($groups);
    }

    /**
     * @param array $subsetKeys
     * @param bool $matchFirst
     * @return $this
     */
    public function filterHasSubsetKeyOf($subsetKeys, $matchFirst = false)
    {
        $subsets = [];
        foreach ($subsetKeys as $k) {
            $subsets[] = [ $k => '' ];
        }
        $groups = GroupHelper::findGroupsHasSubsetOf($this->groups, $subsets, true, $matchFirst);
        return $this->cloneMe()->setGroups($groups);
    }


}
