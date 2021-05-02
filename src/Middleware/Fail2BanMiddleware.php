<?php namespace Fail2Ban\Middleware;

use Closure;
use \Log;
use Illuminate\Http\Response;

class Fail2BanMiddleware {

    protected $cache = null;
    public function __construct() {
        $this->cache = app("Fail2BanCache");
    }

    public function handle($request, Closure $next)
    {
        $ipAddress = $request->ip();
        $path = $request->path();

        if( $this->isBanned($ipAddress) )
        {
            return new Response('Banned', 503);
        }

        $knownRoutes = app()->router->getRoutes()->getRoutes();

        $matchRoute = null;
        foreach($knownRoutes as $route)
        {
            if( !in_array($request->method(), $route->methods) ) 
                continue;

            if( $route->uri === $request->path() ) {
                $matchRoute = $route;
                break;
            };
        }
        
        if( is_null($matchRoute) )
        {
            // process 404
            $this->addToBanList($ipAddress, $path);
        }
        
        try {
            $response = $next($request);
        } catch(\Error|\Exception $ex) {
            $response = (object) [
                'getStatusCode' => function(){ return 500; },
                'exception' => $ex
            ];
        }
        
        if( ! ($response->getStatusCode() >= 200 && $response->getStatusCode() <= 302 ) )
        {
            // process 401|403|500
            $this->addToBanList($ipAddress, $path);

            if( isset($response->exception) )
                throw $response->exception;
        }

        return $response;
    }

    protected function getFailCount( $ip )
    {
        return $this->cache->get("fail2ban:track:$ip") ?? 0;
    }

    protected function getIpAddress( $request )
    {
        return $request->headers('x-forwarded-for');
    }

    protected function addToBanList( $ip, $path )
    {
        if( !$this->cache->exists("fail2ban:track:$ip"))
        {
            $this->cache->set("fail2ban:track:$ip", 0);
        } else if(!$this->cache->exists("fail2ban:jail:$ip") && $this->getFailCount( $ip ) >= 10) {
            Log::channel('fail2ban')->info("UnBan $ip $path");
            $this->cache->set("fail2ban:track:$ip", 0);
        }

        $this->cache->incr("fail2ban:track:$ip");

        if( $this->getFailCount( $ip ) >= 10 )
        {
            $this->ban($ip, $path);
        }
    }

    protected function ban( $ip, $uri )
    {
        Log::channel('fail2ban')->info("Ban $ip $uri");
        if( !$this->cache->exists("fail2ban:jail:$ip") )
        {
            $this->cache->set("fail2ban:jail:$ip", 1);
        }

        $this->cache->expire("fail2ban:jail:$ip", 5);
    }

    protected function isBanned( $ip )
    {
        if( $this->cache->exists("fail2ban:jail:$ip") )
        {
            return true;
        }

        return false;
    }
}