<?php

declare(strict_types=1);

namespace K2gl\Sshsig;

use K2gl\Sshsig\Exception\SigningException;
use K2gl\Sshsig\Internal\Der;
use K2gl\Sshsig\Internal\SshWriter;
use OpenSSLAsymmetricKey;

/**
 * An RSA or ECDSA {@see SigningKey} backed by ext-openssl. RSA produces
 * `rsa-sha2-256`/`rsa-sha2-512` signatures (chosen by the SSHSIG hash
 * algorithm); ECDSA produces `ecdsa-sha2-nistp256/384/521` per the key's curve.
 */
final class OpensslSigningKey implements SigningKey
{
    /** @param array<string, mixed> $details */
    private function __construct(
        private readonly OpenSSLAsymmetricKey $key,
        private readonly array $details,
    ) {}

    public static function fromKey(OpenSSLAsymmetricKey $key): self
    {
        $details = openssl_pkey_get_details($key);

        if ($details === false) {
            throw new SigningException('Could not read the private key details.');
        }

        return new self(key: $key, details: $details);
    }

    public static function fromPem(string $pem, ?string $passphrase = null): self
    {
        $key = openssl_pkey_get_private($pem, $passphrase);

        if ($key === false) {
            throw new SigningException('Could not load the private key.');
        }

        return self::fromKey($key);
    }

    public function publicKey(): SshPublicKey
    {
        if (($this->details['type'] ?? null) === OPENSSL_KEYTYPE_RSA) {
            $rsa = $this->rsa();
            $blob = (new SshWriter)
                ->putString('ssh-rsa')
                ->putMpint($rsa['e'])
                ->putMpint($rsa['n'])
                ->bytes();
        } elseif (($this->details['type'] ?? null) === OPENSSL_KEYTYPE_EC) {
            [$curve, $size] = $this->ecParameters();
            $ec = $this->ec();
            $point = "\x04" . self::pad($ec['x'], $size) . self::pad($ec['y'], $size);
            $blob = (new SshWriter)
                ->putString('ecdsa-sha2-' . $curve)
                ->putString($curve)
                ->putString($point)
                ->bytes();
        } else {
            throw new SigningException('Unsupported key type; expected RSA or EC.');
        }

        return SshPublicKey::fromBlob($blob);
    }

    public function signTosign(string $tosign, string $hashAlgorithm): array
    {
        if (($this->details['type'] ?? null) === OPENSSL_KEYTYPE_RSA) {
            [$algorithm, $opensslAlgorithm] = match ($hashAlgorithm) {
                'sha256' => ['rsa-sha2-256', OPENSSL_ALGO_SHA256],
                'sha512' => ['rsa-sha2-512', OPENSSL_ALGO_SHA512],
                default => throw new SigningException(sprintf('Unsupported RSA hash algorithm "%s".', $hashAlgorithm)),
            };

            if (! openssl_sign($tosign, $signature, $this->key, $opensslAlgorithm)) {
                throw new SigningException('RSA signing failed.');
            }

            return [$algorithm, $signature];
        }

        if (($this->details['type'] ?? null) === OPENSSL_KEYTYPE_EC) {
            [$curve, , $opensslAlgorithm] = $this->ecParameters();

            if (! openssl_sign($tosign, $der, $this->key, $opensslAlgorithm)) {
                throw new SigningException('ECDSA signing failed.');
            }
            [$r, $s] = Der::parseEcdsaSignature($der);
            $bytes = (new SshWriter)
                ->putString($r)
                ->putString($s)
                ->bytes();

            return ['ecdsa-sha2-' . $curve, $bytes];
        }

        throw new SigningException('Unsupported key type; expected RSA or EC.');
    }

    /** @return array{0: string, 1: int, 2: int} [ssh curve id, field byte length, openssl hash] */
    private function ecParameters(): array
    {
        return match ($this->curveName()) {
            'prime256v1', 'secp256r1' => ['nistp256', 32, OPENSSL_ALGO_SHA256],
            'secp384r1' => ['nistp384', 48, OPENSSL_ALGO_SHA384],
            'secp521r1' => ['nistp521', 66, OPENSSL_ALGO_SHA512],
            default => throw new SigningException(sprintf('Unsupported EC curve "%s".', $this->curveName())),
        };
    }

    /** @return array{e: string, n: string} */
    private function rsa(): array
    {
        $rsa = $this->details['rsa'] ?? null;

        if (! is_array($rsa) || ! isset($rsa['e'], $rsa['n']) || ! is_string($rsa['e']) || ! is_string($rsa['n'])) {
            throw new SigningException('Malformed RSA key details.');
        }

        return ['e' => $rsa['e'], 'n' => $rsa['n']];
    }

    /** @return array{x: string, y: string} */
    private function ec(): array
    {
        $ec = $this->details['ec'] ?? null;

        if (! is_array($ec) || ! isset($ec['x'], $ec['y']) || ! is_string($ec['x']) || ! is_string($ec['y'])) {
            throw new SigningException('Malformed EC key details.');
        }

        return ['x' => $ec['x'], 'y' => $ec['y']];
    }

    private function curveName(): string
    {
        $ec = $this->details['ec'] ?? null;
        $name = is_array($ec) ? ($ec['curve_name'] ?? null) : null;

        return is_string($name) ? $name : '';
    }

    private static function pad(string $coordinate, int $length): string
    {
        $coordinate = ltrim($coordinate, "\x00");

        if (strlen($coordinate) > $length) {
            throw new SigningException('EC coordinate exceeds the curve size.');
        }

        return str_pad($coordinate, $length, "\x00", STR_PAD_LEFT);
    }
}
