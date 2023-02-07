<?php

declare(strict_types=1);

namespace Iodev\Whois\Container\Builtin;

use \Psr\Container\ContainerInterface;

class Container implements ContainerInterface
{
    public const ID_COMMON_CLASS_INSTANTIATOR = '@CommonClassInstantiator';

    protected array $items = [];

    public function __construct()
    {
    }

    public function get(string $id): mixed
    {
        $has = $this->has($id);
        $commonClassNeeded = !$has && $this->has(static::ID_COMMON_CLASS_INSTANTIATOR) && class_exists($id);
        
        if (!$has && !$commonClassNeeded) {
            throw new NotFoundException("Not found '$id'");
        }

        try {
            if ($commonClassNeeded) {
                $fn = $this->items[static::ID_COMMON_CLASS_INSTANTIATOR];
            } else {
                $fn = $this->items[$id];
            }
            return $fn($this, $id);
        } catch (\Throwable $e) {
            throw new ContainerException($e->getMessage(), $e->getCode(), $e);
        }
    }

    public function has(string $id): bool
    {
        return array_key_exists($id, $this->items);
    }

    public function bind(string $id, callable $fn): static
    {
        $this->items[$id] = $fn;
        return $this;
    }

    public function bindMany(array $items): static
    {
        foreach ($items as $id => $fn) {
            $this->bind($id, $fn);
        }
        return $this;
    }
}
