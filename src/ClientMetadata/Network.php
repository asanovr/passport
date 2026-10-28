<?php

namespace Laravel\Passport\ClientMetadata;

use Closure;
use Laravel\Passport\Passport;

/**
 * Decides which hosts a document may be fetched from.
 *
 * @internal
 */
class Network
{
    /**
     * The IPv4 ranges that are not globally reachable, as CIDR blocks.
     *
     * @var string[]
     */
    protected const NON_GLOBAL_IPV4 = [
        '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12',
        '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15',
        '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
    ];

    /**
     * The IPv6 ranges inside the global unicast block that are not globally reachable, as CIDR blocks.
     *
     * @var string[]
     */
    protected const NON_GLOBAL_IPV6 = [
        '2001::/32', '2001:2::/48', '2001:10::/28', '2001:db8::/32', '2002::/16', '3fff::/20',
    ];

    /**
     * Get the addresses of the given host, every one of which is globally reachable.
     *
     * @return string[]
     *
     * @throws \Laravel\Passport\ClientMetadata\UnusableDocumentException
     */
    public function publicAddresses(string $host): array
    {
        $host = trim($host, '[]');

        $addresses = filter_var($host, FILTER_VALIDATE_IP) !== false ? [$host] : $this->resolve($host);

        if ($addresses === []) {
            throw new UnusableDocumentException('the host does not resolve to any address');
        }

        foreach ($addresses as $address) {
            if (! $this->isGlobal($address)) {
                throw new UnusableDocumentException("the host resolves to a non-public address ({$address})");
            }
        }

        return $addresses;
    }

    /**
     * Determine if connections can be pinned to the vetted addresses.
     */
    public function canPin(): bool
    {
        return extension_loaded('curl') && defined('CURLOPT_RESOLVE');
    }

    /**
     * Determine if the given IP address is globally reachable.
     */
    public function isGlobal(string $address): bool
    {
        $packed = @inet_pton($address);

        if ($packed === false) {
            return false;
        }

        if (strlen($packed) === 16) {
            // IPv4-mapped (::ffff:0:0/96) and IPv4-compatible (::/96) forms stand for their IPv4 address.
            if (str_starts_with($packed, str_repeat("\0", 10)."\xff\xff") || str_starts_with($packed, str_repeat("\0", 12))) {
                $packed = substr($packed, 12);
            }
        }

        if (strlen($packed) === 4) {
            return ! $this->inAny($packed, static::NON_GLOBAL_IPV4);
        }

        // Only 2000::/3 is global unicast; the rest is reserved, local or multicast.
        return $this->inBlock($packed, '2000::/3') && ! $this->inAny($packed, static::NON_GLOBAL_IPV6);
    }

    /**
     * Resolve the A and AAAA answers of the given host.
     *
     * @return string[]
     */
    protected function resolve(string $host): array
    {
        if (Passport::$clientMetadataHostResolver instanceof Closure) {
            return array_values((Passport::$clientMetadataHostResolver)($host));
        }

        $addresses = @gethostbynamel($host) ?: [];

        foreach (@dns_get_record($host, DNS_AAAA) ?: [] as $record) {
            $addresses[] = $record['ipv6'];
        }

        return array_values(array_unique($addresses));
    }

    /**
     * Determine if the packed address is inside any of the given CIDR blocks.
     *
     * @param  string[]  $blocks
     */
    protected function inAny(string $packed, array $blocks): bool
    {
        foreach ($blocks as $block) {
            if ($this->inBlock($packed, $block)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine if the packed address is inside the given CIDR block.
     */
    protected function inBlock(string $packed, string $block): bool
    {
        [$network, $bits] = explode('/', $block);

        $network = (string) inet_pton($network);

        if (strlen($network) !== strlen($packed)) {
            return false;
        }

        $bits = (int) $bits;
        $bytes = intdiv($bits, 8);

        if (substr($packed, 0, $bytes) !== substr($network, 0, $bytes)) {
            return false;
        }

        if ($bits % 8 === 0) {
            return true;
        }

        $mask = (0xFF << (8 - $bits % 8)) & 0xFF;

        return (ord($packed[$bytes]) & $mask) === (ord($network[$bytes]) & $mask);
    }
}
