<?php namespace Fail2Ban\Providers;

use Illuminate\Support\ServiceProvider as BaseServiceProvider;
use Fail2Ban\Middlewares\Fail2BanMiddleware;
use Fail2Ban\Fail2BanCache;
use Fail2Ban\HttpKernel;

class ServiceProvider extends BaseServiceProvider {
    /**
     * Register any application services.
     *
     * @return void
     */
    public function boot()
    {
        $this->app->bind(
            "Fail2BanCache", 
            function($app) {
                return new Fail2BanCache();
            }
        );

        config([
            'logging.channels' => array_merge(config('logging.channels'), [
                'fail2ban' => [
                    'driver' => 'daily',
                    'path' => storage_path('logs/fail2ban.log'),
                    'level' => env('LOG_LEVEL', 'debug'),
                    'days' => 14,
                ]
            ])
        ]);
    }
}