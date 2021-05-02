<?php namespace Fail2Ban;

class Fail2BanCache extends \Predis\Client {

    public function __construct()
    {
        parent::__construct([
            'scheme' => 'tcp',
            'host'   => config("REDIS_HOST", "cache"),
            'port'   => config("REDIS_PORT", 6379),
        ]);
    }
}