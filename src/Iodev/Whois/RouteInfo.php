<?php


namespace Iodev\Whois;


class RouteInfo
{
    /**
     * @var string
     */
    private $route;

    /**
     * @var string
     */
    private $route6;

    /**
     * @var string
     */
    private $descr;

    /**
     * @var string
     */
    private $origin;

    /**
     * @var string
     */
    private $mntBy;

    /**
     * @var string
     */
    private $changed;

    /**
     * @var string
     */
    private $source;

    /**
     * @return string
     */
    public function getRoute()
    {
        return $this->route;
    }

    /**
     * @param string $route
     */
    public function setRoute($route)
    {
        $this->route = $route;
    }

    /**
     * @return string
     */
    public function getRoute6()
    {
        return $this->route6;
    }

    /**
     * @param string $route6
     */
    public function setRoute6($route6)
    {
        $this->route6 = $route6;
    }

    /**
     * @return string
     */
    public function getDescr()
    {
        return $this->descr;
    }

    /**
     * @param string $descr
     */
    public function setDescr($descr)
    {
        $this->descr = $descr;
    }

    /**
     * @return string
     */
    public function getOrigin()
    {
        return $this->origin;
    }

    /**
     * @param string $origin
     */
    public function setOrigin($origin)
    {
        $this->origin = $origin;
    }

    /**
     * @return string
     */
    public function getMntBy()
    {
        return $this->mntBy;
    }

    /**
     * @param string $mntBy
     */
    public function setMntBy($mntBy)
    {
        $this->mntBy = $mntBy;
    }

    /**
     * @return string
     */
    public function getChanged()
    {
        return $this->changed;
    }

    /**
     * @param string $changed
     */
    public function setChanged($changed)
    {
        $this->changed = $changed;
    }

    /**
     * @return string
     */
    public function getSource()
    {
        return $this->source;
    }

    /**
     * @param string $source
     */
    public function setSource($source)
    {
        $this->source = $source;
    }
}
