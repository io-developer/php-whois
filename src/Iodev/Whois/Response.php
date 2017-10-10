<?php

namespace Iodev\Whois;

use Iodev\Whois\Helpers\ResponseHelper;

class Response
{
    /**
     * @param string $domain
     * @param string $content
     * @return Response
     */
    public static function create($domain, $content)
    {
        $r = new Response($domain, $content);
        $r->groups = ResponseHelper::contentToGroups($content);
        return $r;
    }

    /**
     * @param string $domain
     * @param string $content
     */
    public function __construct($domain = "", $content = "")
    {
        $this->domain = $domain;
        $this->content = $content;
    }

    /** @var string */
    public $domain;
    
    /** @var string */
    public $content;
    
    /** @var ResponseGroup[] */
    public $groups = [];
}
