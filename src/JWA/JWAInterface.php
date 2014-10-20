<?php

namespace Tc\JOSE\JWA;

/**
 * Interface JwaInterface
 *
 * @package Tc\JOSE\JWA
 */
interface JWAInterface
{
    /**
     * Signs a JWT
     *
     * @param $input
     * @param $key
     * @return mixed
     */
    public function sign($input, $key);

    /**
     * Verifies that the JWT's signature is valid
     *
     * @param $key
     * @param $signature
     * @param $input
     * @return mixed
     */
    public function verify($key, $signature, $input);
}
