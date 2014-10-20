<?php

namespace Tc\JOSE;

use Tc\JOSE\Exception\JWAException;
use Tc\JOSE\JWA\JWAInterface;
use Tc\JOSE\Util\Base64Url;

/**
 * JWS
 *
 * @package Tc\JOSE
 * @author Carl Craig <carlcraig@3c-studios.com>
 */
class JWS extends JWT
{
    /**
     * @var string the JSON Web Signature
     */
    protected $signature;

    /**
     * @var bool if the JWS has been signed
     */
    protected $isSigned = false;

    /**
     * @var JWAInterface
     */
    protected $jwa;

    /**
     * Create a new JWS
     */
    public function __construct()
    {
        $this->header = array();
        $this->payload = array();
    }

    /**
     * Get the JSON Web Signature or null if the JWS is not signed.
     *
     * @return null|string The Signature or null if the JWS is not signed
     */
    public function getSignature()
    {
        if ($this->isSigned() || $this->signature) {
            return $this->signature;
        }

        return null;
    }

    /**
     * Set the signature of the JWS
     *
     * @param $signature string The new signature
     */
    public function setSignature($signature)
    {
        $this->signature = $signature;
    }

    /**
     * Check to see if the JWS is signed
     *
     * @return bool is the JWS signed
     */
    public function isSigned()
    {
        return $this->isSigned;
    }

    /**
     * Signs the JWS
     *
     * @param $algorithm string
     * @param $key
     * @return mixed|string the JWS signature
     */
    public function sign($algorithm, $key)
    {
        $this->header['alg'] = $algorithm;
        $this->header['typ'] = 'JOSE';
        $this->signature = $this->getJWA()->sign($this->generateJWSSigningInput(), $key);
        $this->isSigned = true;

        return $this->signature;
    }

    /**
     * Verify the JWS signature
     *
     * @param $key
     * @return bool
     */
    public function verify($key)
    {
        try {
            return $this->getJWA()->verify($key, $this->getSignature(), $this->generateJWSSigningInput());
        } catch (JWAException $e) {
            return false;
        }
    }

    /**
     * Override JWT Validate Method, to Verify JWS before calling JWT validate
     *
     * @param string $key
     * @param bool $checkExpires
     * @return bool
     */
    public function validate($key = '', $checkExpires = true)
    {
        return $this->verify($key) ? parent::validate($key, $checkExpires) : false;
    }

    /**
     * Get the JWS Compact Serialization string
     *
     * This is the Base64Url encoded Header.Payload.Signature
     *
     * @return string The JWS Compact Serialization
     */
    public function serialize()
    {
        return sprintf('%s.%s', $this->generateJWSSigningInput(), Base64Url::encode($this->getSignature()));
    }

    /**
     * Returns the JWA class
     *
     * @return JWAInterface
     * @throws JWAException
     */
    protected function getJWA()
    {
        if (!$this->jwa) {
            preg_match('/(RS|ES|HS|none)(256|384|512)?/i', $this->header['alg'], $algorithm);
            if (!$algorithm || count($algorithm) < 3 && $algorithm[1] !== 'none') {
                throw new JWAException(
                    'Unsupported JWA, Allowed Algorithms: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512'
                );
            }
            $jwaClass = sprintf("Tc\\JOSE\\JWA\\%s", $algorithm[1]);
            if (class_exists($jwaClass)) {
                $this->jwa = new $jwaClass($algorithm[2]);
            } else {
                throw new JWAException(
                    'Unsupported JWA, Allowed Algorithms: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512'
                );
            }
        }

        return $this->jwa;
    }
}
