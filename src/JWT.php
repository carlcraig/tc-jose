<?php

namespace Tc\JOSE;

use InvalidArgumentException;
use Tc\JOSE\Exception\JSONException;
use Tc\JOSE\Util\Base64Url;
use Tc\JOSE\Util\JSON;

/**
 * JWT
 *
 * @package Tc\JOSE
 * @author Carl Craig <carlcraig@3c-studios.com>
 */
class JWT
{
    /**
     * @var array The JOSE Header
     */
    protected $header;

    /**
     * @var array The JWT Claims Set (Payload)
     */
    protected $payload;

    /**
     * Get the JWT header array
     *
     * @return array The JOSE Header
     */
    public function getHeader()
    {
        return $this->header;
    }

    /**
     * Set the JWT header array
     *
     * @param array $header The new JOSE Header
     */
    public function setHeader($header)
    {
        $this->header = $header;
    }

    /**
     * Get the JWT payload
     *
     * @return array The JWT Claims Set (Payload)
     */
    public function getPayload()
    {
        return $this->payload;
    }

    /**
     * Set the JWT payload
     *
     * This will set the "iat" (Issued At) claim if it is not already set
     *
     * @param array $payload The new JWT Claims Set (Payload)
     */
    public function setPayload($payload)
    {
        $this->payload = $payload;
    }

    /**
     * Set the JWT Issued At Claim
     *
     * @param \DateTime $iat
     */
    public function setIssuedAt(\DateTime $iat = null)
    {
        if (!$iat) {
            $iat = new \DateTime('now');
        }
        $this->payload['iat'] = $iat->format('U');
    }

    /**
     * Set the JWT Time To Live - EXP Claim
     *
     * @param $time
     */
    public function setExpires($time)
    {
        if ($time instanceof \DateTime) {
            $exp = $time;
        } else {
            $exp = new \DateTime('now');
            $exp->modify('+' . $time . ' seconds');
        }

        $this->payload['exp'] = $exp->format('U');
    }

    /**
     * Checks to see if the JWT has Expired
     */
    public function isExpired()
    {
        return isset($this->payload['exp']) ? new \DateTime('now') > \DateTime::createFromFormat('U', $this->payload['exp']) : false;
    }

    /**
     * Validates the JWT, will be overridden by JWS and JWE to verify or decrypt before checking JWT validity
     *
     * @param string $key
     * @param bool $checkExpires
     * @return bool
     */
    public function validate($key = '', $checkExpires = true)
    {
        return $checkExpires ? ! $this->isExpired() : true;
    }

    /**
     * Generates the input required for a JWS
     *
     * This will be the Base64Url encoded header and the Base64Url encoded payload, joined with "."
     *
     * @return string
     * @throws Exception\JSONException
     */
    public function generateJWSSigningInput()
    {
        return sprintf(
            "%s.%s",
            Base64Url::encode(JSON::encode($this->getHeader())),
            Base64Url::encode(JSON::encode($this->getPayload()))
        );
    }

    /**
     * Decode a JWS or JWE Compact Serialization string into a JWS or JWE object
     *
     * @param $compactSerializedToken
     */
    public static function decode($compactSerializedToken)
    {
        $parts = explode('.', $compactSerializedToken);
        if (count($parts) === 3) {
            $jws = new JWS();
            try {
                $jws->setHeader(JSON::decode(Base64Url::decode($parts[0])));
                $jws->setPayload(JSON::decode(Base64Url::decode($parts[1])));
                $jws->setSignature(Base64Url::decode($parts[2]));
                return $jws;
            } catch (JSONException $e) {
                throw new InvalidArgumentException('The JWS is Invalid or Malformed');
            }
        } elseif (count($parts) === 5) {
            throw new InvalidArgumentException('The JOSE token is a JWE which is currently not supported');
        }
        throw new InvalidArgumentException('The JOSE token is Invalid or Malformed');
    }
}
