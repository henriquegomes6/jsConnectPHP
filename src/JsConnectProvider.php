<?php

namespace HenriqueGomes6;

use HenriqueGomes6\JsConnect;
use Illuminate\Support\ServiceProvider;

class JsConnectProvider extends ServiceProvider
{
    protected $defer = true;

    public function boot()
    {
        $this->publishes(
            [
                __DIR__ . '/config/jsconnect.php' => $this->getConfigPath('jsconnect.php'),
            ], 'config'
        );
    }

    public function register()
    {
        $this->app->bind('HenriqueGomes6\JsConnect', function ($app) {
            $env       = config('jsconnect');
            $jsconnect = new JsConnect($env['clientId'], $env['secret']);
            return $jsconnect;
        });
    }
    private function getConfigPath($path = '')
    {
        return $this->app->basePath() . '/config' . ($path ? '/' . $path : $path);
    }

    public function provides()
    {
        return [JsConnect::class];
    }

}
