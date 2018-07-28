<?php

namespace Iodev\Whois\Helpers;

class GroupFilter
{
    use GroupTrait;

    /**
     * @param array $groups
     * @return $this
     */
    public static function create($groups = [])
    {
        $m = new self();
        $m->setGroups($groups);
        return $m;
    }

    /**
     * @param string $domain
     * @param string[] $domainKeys
     * @return $this
     */
    public function filterIsDomain($domain, $domainKeys)
    {
        $groups = GroupHelper::findDomainGroups(
            $this->groups,
            $domain,
            $domainKeys,
            $this->matchFirstOnly
        );
        return $this->setGroups($groups);
    }

    /**
     * @param array $subsets
     * @return $this
     */
    public function filterHasSubsetOf($subsets)
    {
        $subsets = GroupHelper::renderSubsets($subsets, $this->subsetParams);
        $groups = GroupHelper::findGroupsHasSubsetOf(
            $this->groups,
            $subsets,
            $this->ignoreCase,
            $this->matchFirstOnly
        );
        return $this->setGroups($groups);
    }

    /**
     * @param array $subsetKeys
     * @return $this
     */
    public function filterHasSubsetKeyOf($subsetKeys)
    {
        $subsets = [];
        foreach ($subsetKeys as $k) {
            $subsets[] = [ $k => '' ];
        }
        $groups = GroupHelper::findGroupsHasSubsetOf(
            $this->groups,
            $subsets,
            $this->ignoreCase,
            $this->matchFirstOnly
        );
        return $this->setGroups($groups);
    }

    /**
     * @return $this
     */
    public function filterHasHeader()
    {
        $groups = GroupHelper::findGroupsHasSubsetOf(
            $this->groups,
            [[ $this->headerKey => '' ]],
            $this->ignoreCase,
            $this->matchFirstOnly
        );
        return $this->setGroups($groups);
    }

    /**
     * @return GroupSelector
     */
    public function toSelector()
    {
        return GroupSelector::create($this->groups)
            ->useIgnoreCase($this->ignoreCase)
            ->useMatchFirstOnly($this->matchFirstOnly)
            ->setHeaderKey($this->headerKey)
            ->setSubsetParams($this->subsetParams);
    }
}
