<?php

declare(strict_types=1);

namespace Iodev\Whois\Selection;

trait GroupTrait
{
    protected array $groups = [];
    protected string $headerKey = '$header';
    protected array $domainKeys = [];
    protected array $subsetParams = [];
    protected bool $matchFirstOnly = false;
    protected bool $ignoreCase = false;


    public function cloneMe(): static
    {
        return clone $this;
    }

    public function isEmptyGroups(): bool
    {
        return empty($this->groups);
    }

    public function getFirstGroup(): ?array
    {
        return count($this->groups) > 0 ? $this->groups[0] : null;
    }

    public function getGroups(): array
    {
        return $this->groups;
    }

    public function setGroups(array $groups): static
    {
        $this->groups = $groups;
        return $this;
    }

    public function setOneGroup(?array $group): static
    {
        $this->groups = !empty($group) ? [ $group ] : [];
        return $this;
    }

    public function useFirstGroup(): static
    {
        return $this->setOneGroup($this->getFirstGroup());
    }

    public function useFirstGroupOr(?array $group): static
    {
        $first = $this->getFirstGroup();
        return $this->setOneGroup(!empty($first) ? $first : $group);
    }

    public function mergeGroups(): static
    {
        $finalGroup = [];
        foreach ($this->groups as $group) {
            $finalGroup = array_merge_recursive($finalGroup, $group);
        }
        $this->groups = [ $finalGroup ];
        return $this;
    }

    public function setHeaderKey(string $key): static
    {
        $this->headerKey = $key;
        return $this;
    }

    public function setDomainKeys(array $keys): static
    {
        $this->domainKeys = $keys;
        return $this;
    }

    public function setSubsetParams(array $params): static
    {
        $this->subsetParams = $params;
        return $this;
    }

    public function useMatchFirstOnly(bool $yes): static
    {
        $this->matchFirstOnly = (bool)$yes;
        return $this;
    }

    public function useIgnoreCase(bool $yes): static
    {
        $this->ignoreCase = (bool)$yes;
        return $this;
    }
}
