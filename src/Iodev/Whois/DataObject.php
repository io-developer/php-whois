<?php

namespace Iodev\Whois;

class DataObject
{
    /**
     * @param array $data
     */
    public function __construct(array $data = [])
    {
        $this->data = $data;
    }

    /** @var array */
    protected $data;

    /** @var array */
    protected $dataDefault = [];

    /** @var array */
    protected $dataAlias = [];

    /**
     * @param string $key
     * @return mixed
     */
    public function __get($key)
    {
        $default = $this->dataDefault[$key] ?? null;
        $key = $this->dataAlias[$key] ?? $key;
        return $this->get($key, $default);
    }

    /**
     * @param $key
     * @param mixed $default
     * @return mixed
     */
    public function get($key, $default = null)
    {
        return $this->data[$key] ?? $default;
    }

    /**
     * @return array
     */
    public function getData(): array
    {
        return $this->data;
    }
}
