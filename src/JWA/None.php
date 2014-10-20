<?php

namespace Tc\JOSE\JWA;

/**
 * Class None
 *
 * @package Tc\JOSE\JWA
 */
class None implements JWAInterface
{
    /**
     * @inheritdoc
     */
    public function sign($input, $key)
    {
        return '';
    }

    /**
     * @inheritdoc
     */
    public function verify($key, $signature, $input)
    {
        return $signature === '';
    }
}
