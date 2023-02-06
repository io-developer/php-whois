<?php

declare(strict_types=1);

namespace Iodev\Whois\Traits;

trait TagContainerTrait
{
    protected array $tags = [];

    public function tagWith(string $tag, mixed $val = true): static
    {
        $this->tags[$tag] = $val;
        return $this;
    }

    public function hasTag(string $tag): bool
    {
        return array_key_exists($tag, $this->tags);
    }

    public function hasAnyTag(array $tags): bool
    {
        foreach ($tags as $tag) {
            if (array_key_exists($tag, $this->tags)) {
                return true;
            }
        }
        return false;
    }

    public function getTags(): array
    {
        return array_keys($this->tags);
    }

    public function getTagValues(array $tags = null): array
    {
        if ($tags === null) {
            return $this->tags;
        }
        $result = [];
        foreach ($tags as $tag) {
            if (array_key_exists($tag, $this->tags)) {
                $result[$tag] = $this->tags[$tag];
            }
        }
        return $result;
    }

    public function getTagValue(string $tag, mixed $def = null): mixed
    {
        return array_key_exists($tag, $this->tags) ? $this->tags[$tag] : $def;
    }
}
