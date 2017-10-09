<?php

namespace Iodev\Whois;

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
        $groups = preg_split('/([\s\t]*\r?\n){2,}/', $content);
        foreach ($groups as $group) {
            $data = [];
            preg_match_all('/^\s*(( *[\w-]+)+):[ \t]+(.+)$/mui', $group, $matches);
            foreach ($matches[1] as $index => $key) {
                $val = $matches[3][$index];
                if (!key_exists($key, $data)) {
                    $data[$key] = $val;
                } elseif (is_array($data[$key])) {
                    $data[$key][] = $val;
                } else {
                    $data[$key] = [ $data[$key], $val ];
                }
            }
            if (count($data) > 2) {
                $r->groups[] = new ResponseGroup($data);
            }
        }
        return $r;
    }

    /**
     * @param string $requestedDomain
     * @param string $content
     */
    public function __construct($requestedDomain = "", $content = "")
    {
        $this->requestedDomain = $requestedDomain;
        $this->content = $content;
    }

    /** @var string */
    public $requestedDomain;
    
    /** @var string */
    public $content;
    
    /** @var ResponseGroup[] */
    public $groups = [];
    
    /**
     * @return bool
     */
    public function isEmpty()
    {
        return (count($this->groups) < 1);
    }
}
