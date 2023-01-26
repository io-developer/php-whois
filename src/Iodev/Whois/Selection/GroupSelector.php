<?php

declare(strict_types=1);

namespace Iodev\Whois\Selection;

use Iodev\Whois\Tool\DateTool;
use Iodev\Whois\Tool\DomainTool;

class GroupSelector
{
    use GroupTrait;


    protected array $items = [];


    public function __construct(
        protected DomainTool $domainTool,
        protected DateTool $dateTool,
    ) {}

    public function isEmpty(): bool
    {
        return empty($this->items);
    }

    public function getAll(): array
    {
        return $this->items;
    }

    /**
     * First item
     */
    public function getFirstItem(mixed $default = null): mixed
    {
        return count($this->items) > 0 ? reset($this->items) : $default;
    }

    /**
     * First non-array value
     */
    public function getFirst(mixed $default = null): mixed
    {
        $first = $this->getFirstItem();
        while (is_array($first)) {
            $first = count($first) > 0 ? reset($first) : null;
        }
        return $first !== null ? $first : $default;
    }

    public function clean(): static
    {
        $this->items = [];
        return $this;
    }

    public function selectItems(array $items): static
    {
        $this->items = array_merge($this->items, $items);
        return $this;
    }

    /**
     * @param string[] $keys
     */
    public function selectKeys(array $keys): static
    {
        foreach ($this->groups as $group) {
            $matches = GroupHelper::matchKeys($group, $keys, $this->matchFirstOnly);
            foreach ($matches as $match) {
                if (is_array($match)) {
                    $this->items = array_merge($this->items, $match);
                } else {
                    $this->items[] = $match;
                }
            }
        }
        return $this;
    }

    public function selectKeyGroups(array $keyGroups): static
    {
        foreach ($keyGroups as $keyGroup) {
            foreach ($keyGroup as $key) {
                $this->selectKeys([ $key ]);
            }
        }
        return $this;
    }

    public function removeEmpty(): static
    {
        $this->items = array_filter($this->items);
        return $this;
    }

    public function removeDuplicates(): static
    {
        $this->items = array_unique($this->items);
        return $this;
    }

    public function sort(int $flags = SORT_REGULAR): static
    {
        sort($this->items, $flags);
        return $this;
    }

    /**
     * @param callable $fn(array $input): array
     * Transform source items -> to new items (array lengths may be different)
     */
    public function transform(callable $fn): static
    {
        $this->items = $fn($this->items);
        return $this;
    }

    public function map(callable $fn): static
    {
        $this->items = array_map($fn, $this->items);
        return $this;
    }

    public function mapDomain(): static
    {
        foreach ($this->items as &$item) {
            if ($item && preg_match('~([-\pL\d]+\.)+[-\pL\d]+~ui', $item, $m)) {
                $ascii = $this->domainTool->toAscii($m[0]);
                $item = $this->domainTool->filterAscii($ascii);
            } else {
                $item = '';
            }
        }
        return $this;
    }

    public function mapAsciiServer(): static
    {
        foreach ($this->items as &$item) {
            $raw = is_string($item) ? trim($item, '.') : '';
            $ascii = $this->domainTool->toAscii($raw);
            $item = $this->domainTool->filterAscii($ascii);
            if ($item && !preg_match('~^([-\pL\d]+\.)+[-\pL\d]+$~ui', $item)) {
                if (!preg_match('~^[a-z\d]+-norid$~ui', $item)) {
                    $item = '';
                }
            }
        }
        return $this;
    }

    public function mapUnixTime(bool $inverseMMDD = false): static
    {
        return $this->map(function($item) use ($inverseMMDD) {
            return is_string($item)
                ? $this->dateTool->parseDate($item, $inverseMMDD)
                : 0
            ;
        });
    }
}
