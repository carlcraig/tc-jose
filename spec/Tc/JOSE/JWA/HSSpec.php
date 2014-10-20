<?php

namespace spec\Tc\JOSE\JWA;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

/**
 * HSSpec
 *
 * @package spec\Tc\JOSE\JWA
 * @author Carl Craig <carlcraig@3c-studios.com>
 * @mixin \Tc\JOSE\JWA\HS
 */
class HSSpec extends ObjectBehavior
{
    function it_should_not_be_constructed_without_bits()
    {
        $this->shouldThrow(new \InvalidArgumentException('Invalid JWA bits, allowed: 256, 384 or 512'))->during__construct(null);
    }

    function it_should_only_be_constructed_with_valid_bits()
    {
        $this->shouldNotThrow(new \InvalidArgumentException('Invalid JWA bits, allowed: 256, 384 or 512'))->during__construct('256');
        $this->shouldNotThrow(new \InvalidArgumentException('Invalid JWA bits, allowed: 256, 384 or 512'))->during__construct('384');
        $this->shouldNotThrow(new \InvalidArgumentException('Invalid JWA bits, allowed: 256, 384 or 512'))->during__construct('512');
    }

    function it_should_not_be_constructed_with_invalid_bits()
    {
        $this->shouldThrow(new \InvalidArgumentException('Invalid JWA bits, allowed: 256, 384 or 512'))->during__construct('InvalidBits');
    }

    function it_should_verify_a_valid_signature_using_256_bits()
    {
        $this->beConstructedWith('256');
        $this->verify('key', $this->sign('123', 'key'), '123')->shouldReturn(true);
    }

    function it_should_not_verify_an_invalid_signature_using_256_bits()
    {
        $this->beConstructedWith('256');
        $this->verify('key', $this->sign('123', 'key'), '1234')->shouldReturn(false);
        $this->verify('invalidKey', $this->sign('123', 'key'), '123')->shouldReturn(false);
    }

    function it_should_verify_a_valid_signature_using_384_bits()
    {
        $this->beConstructedWith('384');
        $this->verify('key', $this->sign('123', 'key'), '123')->shouldReturn(true);
    }

    function it_should_not_verify_an_invalid_signature_using_384_bits()
    {
        $this->beConstructedWith('384');
        $this->verify('key', $this->sign('123', 'key'), '1234')->shouldReturn(false);
        $this->verify('invalidKey', $this->sign('123', 'key'), '123')->shouldReturn(false);
    }

    function it_should_verify_a_valid_signature_using_512_bits()
    {
        $this->beConstructedWith('512');
        $this->verify('key', $this->sign('123', 'key'), '123')->shouldReturn(true);
    }

    function it_should_not_verify_an_invalid_signature_using_512_bits()
    {
        $this->beConstructedWith('512');
        $this->verify('key', $this->sign('123', 'key'), '1234')->shouldReturn(false);
        $this->verify('invalidKey', $this->sign('123', 'key'), '123')->shouldReturn(false);
    }
}
