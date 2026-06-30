<?php

declare(strict_types=1);

namespace K2gl\Sshsig\Internal;

use K2gl\Sshsig\Exception\SigningException;

/**
 * A minimal DER codec — just enough to wrap an SSH-wire public key into a
 * SubjectPublicKeyInfo PEM that ext-openssl can load, to turn an SSH ECDSA
 * (r, s) pair into the ASN.1 SEQUENCE that openssl_verify() expects, and to
 * read the (r, s) back out of an openssl_sign() result.
 *
 * @internal
 */
final class Der
{
    /** OID 1.2.840.113549.1.1.1 rsaEncryption. */
    public const OID_RSA = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";

    /** OID 1.2.840.10045.2.1 id-ecPublicKey. */
    public const OID_EC = "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";

    /** OID 1.2.840.10045.3.1.7 prime256v1 (NIST P-256). */
    public const OID_P256 = "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";

    /** OID 1.3.132.0.34 secp384r1 (NIST P-384). */
    public const OID_P384 = "\x06\x05\x2b\x81\x04\x00\x22";

    /** OID 1.3.132.0.35 secp521r1 (NIST P-521). */
    public const OID_P521 = "\x06\x05\x2b\x81\x04\x00\x23";

    public const NULL = "\x05\x00";

    public static function sequence(string $contents): string
    {
        return "\x30" . self::length(strlen($contents)) . $contents;
    }

    public static function bitString(string $contents): string
    {
        return "\x03" . self::length(strlen($contents) + 1) . "\x00" . $contents;
    }

    /** A DER INTEGER from an unsigned big-endian magnitude (minimal, sign-safe). */
    public static function integer(string $magnitude): string
    {
        $value = ltrim($magnitude, "\x00");

        if ($value === '') {
            $value = "\x00";
        }

        if ((ord($value[0]) & 0x80) !== 0) {
            $value = "\x00" . $value;
        }

        return "\x02" . self::length(strlen($value)) . $value;
    }

    /** SEQUENCE { INTEGER r, INTEGER s } from two SSH mpint magnitudes. */
    public static function ecdsaSignature(string $r, string $s): string
    {
        return self::sequence(self::integer($r) . self::integer($s));
    }

    /**
     * Read SEQUENCE { INTEGER r, INTEGER s } (an openssl_sign ECDSA result) and
     * return the r and s contents. DER INTEGER content is already minimal,
     * sign-correct big-endian — i.e. exactly the SSH mpint content.
     *
     * @return array{0: string, 1: string}
     */
    public static function parseEcdsaSignature(string $der): array
    {
        $offset = 0;

        if (self::byte($der, $offset++) !== 0x30) {
            throw new SigningException('Expected a DER SEQUENCE in the ECDSA signature.');
        }
        self::readLength($der, $offset);

        return [self::readInteger($der, $offset), self::readInteger($der, $offset)];
    }

    private static function byte(string $bytes, int $index): int
    {
        if (! isset($bytes[$index])) {
            throw new SigningException('Truncated DER in the ECDSA signature.');
        }

        return ord($bytes[$index]);
    }

    private static function readLength(string $bytes, int &$offset): int
    {
        $first = self::byte($bytes, $offset++);

        if ($first < 0x80) {
            return $first;
        }
        $count = $first & 0x7f;
        $length = 0;

        for ($i = 0; $i < $count; $i++) {
            $length = ($length << 8) | self::byte($bytes, $offset++);
        }

        return $length;
    }

    private static function readInteger(string $bytes, int &$offset): string
    {
        if (self::byte($bytes, $offset++) !== 0x02) {
            throw new SigningException('Expected a DER INTEGER in the ECDSA signature.');
        }
        $length = self::readLength($bytes, $offset);
        $value = substr($bytes, $offset, $length);

        if (strlen($value) !== $length) {
            throw new SigningException('Truncated DER INTEGER in the ECDSA signature.');
        }
        $offset += $length;

        return $value;
    }

    private static function length(int $length): string
    {
        if ($length < 0x80) {
            return chr($length & 0xff);
        }
        $bytes = '';

        while ($length > 0) {
            $bytes = chr($length & 0xff) . $bytes;
            $length >>= 8;
        }

        return chr((0x80 | strlen($bytes)) & 0xff) . $bytes;
    }
}
