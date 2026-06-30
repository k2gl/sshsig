<?php

declare(strict_types=1);

namespace K2gl\Sshsig\Internal;

/**
 * A minimal DER encoder — just enough to wrap an SSH-wire public key into a
 * SubjectPublicKeyInfo PEM that ext-openssl can load, and to turn an SSH ECDSA
 * (r, s) pair into the ASN.1 SEQUENCE that openssl_verify() expects.
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
