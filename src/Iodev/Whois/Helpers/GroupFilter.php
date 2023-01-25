<?php

declare(strict_types=1);

namespace Iodev\Whois\Helpers;

use Iodev\Whois\Tool\DomainTool;

class GroupFilter
{
    use GroupTrait;

    public function __construct(
        protected DomainTool $domainTool,
    ) {}

    /**
     * @param string[] $domainKeys
     */
    public function filterIsDomain(string $domain, array $domainKeys): static
    {
        $groups = GroupHelper::findDomainGroups(
            $this->groups,
            $domain,
            $domainKeys,
            $this->matchFirstOnly,
            $this->domainTool,
        );
        return $this->setGroups($groups);
    }

    public function filterHasSubsetOf(array $subsets): static
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

    public function filterHasSubsetKeyOf(array $subsetKeys): static
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

    public function filterHasHeader(): static
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
     * Replaces special empty values by NULL
     */
    public function handleEmpty(array $nullValDict): static
    {
        foreach ($this->groups as $index => &$group) {
            foreach ($group as $k => &$v) {
                if (is_array($v)) {
                    foreach ($v as &$subVal) {
                        if (is_string($subVal) && !empty($nullValDict[(string)$subVal])) {
                            $subVal = null;
                        }
                    }
                } elseif (!empty($nullValDict[(string)$v])) {
                    $v = null;
                }
            }
        }
        return $this;
    }

    public function toSelector(): GroupSelector
    {
        return $this->createSelector()
            ->setGroups($this->groups)
            ->useIgnoreCase($this->ignoreCase)
            ->useMatchFirstOnly($this->matchFirstOnly)
            ->setHeaderKey($this->headerKey)
            ->setSubsetParams($this->subsetParams);
    }

    protected function createSelector(): GroupSelector
    {
        return new GroupSelector($this->domainTool);
    }
}
