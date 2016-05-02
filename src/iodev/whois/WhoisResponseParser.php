<?php

namespace iodev\whois;

/**
 * @author Sergey Sedyshev
 */
class WhoisResponseParser
{
    /**
     * @param string $domain
     * @param string $content
     * @return WhoisResponse
     */
    public function fromString( $domain, $content )
    {
        $r = new WhoisResponse($domain, $content);
        
        $splitted = preg_split('/([\s\t]*\r?\n){2,}/', $content);
        foreach ($splitted as $split) {
            $data = [];    
            preg_match_all('/^\s*(( *[\w-]+)+):[ \t]+(.+)$/mui', $split, $matches);
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
                $r->groups[] = new WhoisResponseGroup($data);
            }
        }
        
        return $r;
    }
}
