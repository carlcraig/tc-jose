<?php

namespace spec\Tc\JOSE\JWA;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

/**
 * RSSpec
 *
 * @package spec\Tc\JOSE\JWA
 * @author Carl Craig <carlcraig@3c-studios.com>
 * @mixin \Tc\JOSE\JWA\RS
 */
class RSSpec extends ObjectBehavior
{
    function it_should_not_be_constructed_without_bits()
    {
        $this->shouldThrow(
            new \InvalidArgumentException('Invalid JWA bits, allowed: 256, 384 or 512')
        )->during__construct(null);
    }

    function it_should_only_be_constructed_with_valid_bits()
    {
        $this->shouldNotThrow(
            new \InvalidArgumentException('Invalid JWA bits, allowed: 256, 384 or 512')
        )->during__construct('256');
        $this->shouldNotThrow(
            new \InvalidArgumentException('Invalid JWA bits, allowed: 256, 384 or 512')
        )->during__construct('384');
        $this->shouldNotThrow(
            new \InvalidArgumentException('Invalid JWA bits, allowed: 256, 384 or 512')
        )->during__construct('512');
    }

    function it_should_not_be_constructed_with_invalid_bits()
    {
        $this->shouldThrow(
            new \InvalidArgumentException('Invalid JWA bits, allowed: 256, 384 or 512')
        )->during__construct('InvalidBits');
    }

    function it_should_verify_a_valid_signature_using_256_bits()
    {
        $this->beConstructedWith('256');
        $this->verify($this->publicKey, $this->sign('123', $this->privateKey), '123')->shouldReturn(true);
    }

    function it_should_not_verify_an_invalid_signature_using_256_bits()
    {
        $this->beConstructedWith('256');
        $this->verify($this->publicKey, $this->sign('123', $this->privateKey), '1234')->shouldReturn(false);
        $this->verify($this->publicKeyInvalid, $this->sign('123', $this->privateKey), '123')->shouldReturn(false);
    }

    function it_should_verify_a_valid_signature_using_384_bits()
    {
        $this->beConstructedWith('384');
        $this->verify($this->publicKey, $this->sign('123', $this->privateKey), '123')->shouldReturn(true);
    }

    function it_should_not_verify_an_invalid_signature_using_384_bits()
    {
        $this->beConstructedWith('384');
        $this->verify($this->publicKey, $this->sign('123', $this->privateKey), '1234')->shouldReturn(false);
        $this->verify($this->publicKeyInvalid, $this->sign('123', $this->privateKey), '123')->shouldReturn(false);
    }

    function it_should_verify_a_valid_signature_using_512_bits()
    {
        $this->beConstructedWith('512');
        $this->verify($this->publicKey, $this->sign('123', $this->privateKey), '123')->shouldReturn(true);
    }

    function it_should_not_verify_an_invalid_signature_using_512_bits()
    {
        $this->beConstructedWith('512');
        $this->verify($this->publicKey, $this->sign('123', $this->privateKey), '1234')->shouldReturn(false);
        $this->verify($this->publicKeyInvalid, $this->sign('123', $this->privateKey), '123')->shouldReturn(false);
    }

    /**
     * Mock the OpenSSL Public, PublicInvalid and Private Keys
     */

    protected $privateKey;
    protected $publicKey;
    protected $publicKeyInvalid;

    function let()
    {
        $publicKey = <<<EOD
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAo+ppLsHjUbRrzMC1HOY4
RbP4Agy1HvOH7KW6s8EKhYif5ik/xT1OUZAgeP+yuyS9NKPLc6Bjky2gGh5aadQI
N2kJ1dtA4rDqhJml1dw2zeizABxDvkmwoWJhn25UAwR5CIoVVhjnES7V4NK5FuP6
XCFJ7vyCCht1AO/uYr/SSBKhsp72WAKPaEO9Wv3pHrQ8pMC9J8dodAava3JfEq1t
MZpp+5Ulw2SLLFdqxGjKYMx35Th5/HjFYvFz7m/kYe9MPOqpqly26aRnJzyNruqP
tBWjnSkkiL/SmUPRuB97Isb0Lq14MtGgDMwxROIy5fjLIJZmpqr+r0Vui/ZdOtSu
D9Ib+TXqujXk7joeRrsNpD/qYqpGBjJomJf2gbM6X4FtYlSHzPlEvaMEWW1T2WqV
Bl7/afcUhS7BP3yFUVGAS1oeKCIzhIv/+OpuMoP9uy6FrAPFWQzelC7qyicGs5tJ
eYFdsoe+sSwR3wo2r1D22/AjgFuVtSxxWgBVowBhnPqvQwBM29icrmaHZE60shhM
x7zxHKyG6YHJ4iF+v3x8q/dCpDVKAiKlHfJZSfIpKAr2dH8Gcjkbcutdoafm6uyc
IMi86z83/F4LEFNR63esHsie40jtQ3c4GjWDjyCCg3ZumoQOl2/5N+HwsloSoY/A
vLtJ1EOkJlT5coeLn+yEHxcCAwEAAQ==
-----END PUBLIC KEY-----
EOD;

        $privateKey = <<<EOD
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,1FCF0B80B6F779952131272A5D7DCF72

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
-----END RSA PRIVATE KEY-----
EOD;

        $publicKeyInvalid = <<<EOD
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAo+ppLsHjUbRrzMC1HOY4
RbP4Agy1HvOH7KW6s8EKhYif5ik/xT1OUZAgeP+yuyS9NKPLc6Bjky2gGh5aadQI
N2kJ1dtA4rDqhJml1dw2zeizABxDvkmwoWJhn25UAwR5CIoVVhjnES7V4NK5FuP6
XCFJ7vyCCht1AO/uYr/SSBKhsp72WAKPaEO9Wv3pHrQ8pMC9J8dodAava3JfEq1t
MZpp+5Ulw2SLLFdqxGjKYMx35Th5/HjFYvFz7m/kYe9MPOqpqly26aRnJzyNruqP
tBWjnSkkiL/SmUPRuB97Isb0Lq14Mtdsfsdfasdasdwe23asdea+r0Vui/ZdOtSu
D9Ib+TXqujXk7joeRrsNpD/qYqpGBjJomJf2gbM6X4FtYlSHzPlEvaMEWW1T2WqV
Bl7/afcUhS7BP3yFUVGAS1oeKCIzhIv/+OpuMoP9uy6FrAPFWQzelC7qyicGs5tJ
eYFdsoe+sSwR3wo2r1D22/AjgFuVtSxxWgBVowBhnPqvQwBM29icrmaHZE60shhM
x7zxHKyG6YHJ4iF+v3x8q/dCpDVKAiKlHfJZSfIpKAr2dH8Gcjkbcutdoafm6uyc
IMi86z83/F4LEFNR63esHsie40jtQ3c4GjWDjyCCg3ZumoQOl2/5N+HwsloSoY/A
vLtJ1EOkJlT5coeLn+yEHxcCAwEAAQ==
-----END PUBLIC KEY-----
EOD;

        $this->privateKey = openssl_pkey_get_private($privateKey, 'test');
        $this->publicKey = openssl_pkey_get_public($publicKey);
        $this->publicKeyInvalid = openssl_pkey_get_public($publicKeyInvalid);
    }
}
