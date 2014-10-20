<?php

namespace Tc\JOSE\JWA;

/**
 * Class HS
 * @package Tc\JOSE\JWA
 */
class HS implements JWAInterface
{
    /**
     * @var string
     */
    private $hashAlgorithm;

    /**
     * @param $bits
     */
    public function __construct($bits)
    {
        $bits = (string) $bits;
        if ($bits !== '256' && $bits !== '384' && $bits !== '512') {
            throw new \InvalidArgumentException('Invalid JWA bits, allowed: 256, 384 or 512');
        }
        $this->hashAlgorithm = 'sha' . $bits;
    }

    /**
     * @inheritdoc
     */
    public function sign($input, $key)
    {
        return hash_hmac($this->hashAlgorithm, $input, $key);
    }

    /**
     * @inheritdoc
     */
    public function verify($key, $signature, $input)
    {
        return $signature === $this->sign($input, $key);
    }
}
