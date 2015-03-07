<?php

namespace Tc\JOSE\JWA;

/**
 * Class BaseESRS
 * @package Tc\JOSE\JWA
 */
class BaseESRS implements JWAInterface
{
    /**
     * @var string/int
     */
    private $hashAlgorithm;

    /**
     * @param $bits
     */
    public function __construct($bits)
    {
        $bits = (string)$bits;
        if ($bits !== '256' && $bits !== '384' && $bits !== '512') {
            throw new \InvalidArgumentException('Invalid JWA bits, allowed: 256, 384 or 512');
        }
        if (version_compare(phpversion(), '5.4.8', '<')) {
            $this->hashAlgorithm = 'SHA' . $bits;
        } else {
            switch ($bits) {
                case '256':
                    $this->hashAlgorithm = OPENSSL_ALGO_SHA256;
                    break;
                case '384':
                    $this->hashAlgorithm = OPENSSL_ALGO_SHA384;
                    break;
                case '512':
                    $this->hashAlgorithm = OPENSSL_ALGO_SHA512;
                    break;
            }
        }
    }

    /**
     * @inheritdoc
     */
    public function sign($input, $key)
    {
        $signature = null;
        openssl_sign($input, $signature, $key, $this->hashAlgorithm);

        return $signature;
    }

    /**
     * @inheritdoc
     */
    public function verify($key, $signature, $input)
    {
        return (bool)openssl_verify($input, $signature, $key, $this->hashAlgorithm);
    }
}
