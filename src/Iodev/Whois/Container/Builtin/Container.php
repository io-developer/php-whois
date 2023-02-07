<?php

declare(strict_types=1);

namespace Iodev\Whois\Container\Builtin;

use \Psr\Container\ContainerInterface;
use \Iodev\Whois\Container\Builtin\Exception\{
    ContainerException,
    NotFoundException,
};

class Container implements ContainerInterface
{
    public const ID_DEFAULT = '@default';

    protected array $items = [];

    public function get(string $id): mixed
    {
        $item = null;
        if ($this->has($id)) {
            $item = $this->items[$id];
        } elseif ($this->has(static::ID_DEFAULT)) {
            $item = $this->items[static::ID_DEFAULT];
        } else {
            throw new NotFoundException("Not found '$id' or @default hander");
        }

        try {
            if (is_callable($item)) {
                return $item($this, $id);
            }
            return $item;
        } catch (\Throwable $e) {
            throw new ContainerException($e->getMessage(), $e->getCode(), $e);
        }
    }

    public function has(string $id): bool
    {
        return array_key_exists($id, $this->items);
    }

    public function bind(string $id, mixed $item): static
    {
        $this->items[$id] = $item;
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
