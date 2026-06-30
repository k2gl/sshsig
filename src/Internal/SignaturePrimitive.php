<?php

declare(strict_types=1);

namespace K2gl\Sshsig\Internal;

/**
 * Verifies the raw signature over the SSHSIG "to be signed" blob, dispatching
 * on the signature algorithm: Ed25519 via ext-sodium, RSA (PKCS#1 v1.5) and
 * ECDSA via ext-openssl. SSH-wire public keys are wrapped into a
 * SubjectPublicKeyInfo PEM so OpenSSL can load them. The key type must match
 * the signature algorithm family, and the whole blob is fed to the primitive
 * (each algorithm applies its own internal hash).
 *
 * @internal
 */
final class SignaturePrimitive
{
    public static function verify(
        string $publicKeyBlob,
        string $signatureAlgorithm,
        string $signedData,
        string $signature,
    ): bool {
        $key = new SshReader($publicKeyBlob);
        $keyType = $key->readString();
        $expectedKeyType = self::keyTypeFor($signatureAlgorithm);

        if ($expectedKeyType === null || $keyType !== $expectedKeyType) {
            return false;
        }

        return match ($signatureAlgorithm) {
            'ssh-ed25519' => self::verifyEd25519(
                key: $key,
                signedData: $signedData,
                signature: $signature,
            ),
            'rsa-sha2-256' => self::verifyRsa(
                key: $key,
                signedData: $signedData,
                signature: $signature,
                algorithm: OPENSSL_ALGO_SHA256,
            ),
            'rsa-sha2-512' => self::verifyRsa(
                key: $key,
                signedData: $signedData,
                signature: $signature,
                algorithm: OPENSSL_ALGO_SHA512,
            ),
            default => self::verifyEcdsa(
                signatureAlgorithm: $signatureAlgorithm,
                key: $key,
                signedData: $signedData,
                signature: $signature,
            ),
        };
    }

    private static function keyTypeFor(string $signatureAlgorithm): ?string
    {
        return match ($signatureAlgorithm) {
            'ssh-ed25519' => 'ssh-ed25519',
            'rsa-sha2-256', 'rsa-sha2-512' => 'ssh-rsa',
            'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521' => $signatureAlgorithm,
            default => null,
        };
    }

    private static function verifyEd25519(SshReader $key, string $signedData, string $signature): bool
    {
        $publicKey = $key->readString();

        if (
            strlen($publicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES
            || strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES
        ) {
            return false;
        }

        return sodium_crypto_sign_verify_detached($signature, $signedData, $publicKey);
    }

    private static function verifyRsa(SshReader $key, string $signedData, string $signature, int $algorithm): bool
    {
        $e = $key->readString();
        $n = $key->readString();
        $spki = Der::sequence(
            Der::sequence(Der::OID_RSA . Der::NULL)
            . Der::bitString(Der::sequence(Der::integer($n) . Der::integer($e)))
        );

        return self::opensslVerify(
            spki: $spki,
            signedData: $signedData,
            signature: $signature,
            algorithm: $algorithm,
        );
    }

    private static function verifyEcdsa(string $signatureAlgorithm, SshReader $key, string $signedData, string $signature): bool
    {
        $parameters = match ($signatureAlgorithm) {
            'ecdsa-sha2-nistp256' => [OPENSSL_ALGO_SHA256, Der::OID_P256],
            'ecdsa-sha2-nistp384' => [OPENSSL_ALGO_SHA384, Der::OID_P384],
            'ecdsa-sha2-nistp521' => [OPENSSL_ALGO_SHA512, Der::OID_P521],
            default => null,
        };

        if ($parameters === null) {
            return false;
        }
        [$algorithm, $curveOid] = $parameters;

        $key->readString(); // curve identifier ("nistpXXX"); the curve is fixed by the key type
        $point = $key->readString();
        $spki = Der::sequence(Der::sequence(Der::OID_EC . $curveOid) . Der::bitString($point));

        $blob = new SshReader($signature);
        $der = Der::ecdsaSignature($blob->readString(), $blob->readString());

        return self::opensslVerify(
            spki: $spki,
            signedData: $signedData,
            signature: $der,
            algorithm: $algorithm,
        );
    }

    private static function opensslVerify(string $spki, string $signedData, string $signature, int $algorithm): bool
    {
        $pem = "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($spki), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
        $key = openssl_pkey_get_public($pem);

        if ($key === false) {
            return false;
        }

        return openssl_verify($signedData, $signature, $key, $algorithm) === 1;
    }
}
