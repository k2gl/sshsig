<?php

declare(strict_types=1);

namespace K2gl\Sshsig\Internal;

use K2gl\Sshsig\Exception\InvalidSignatureException;

/**
 * The SSHSIG armor: a PEM-like wrapper around the base64 of the binary
 * signature blob. It is not RFC 7468 PEM (the label and wrap width differ), so
 * it is parsed directly: locate the markers, strip all whitespace from the
 * body, and base64-decode strictly.
 *
 * @internal
 */
final class Armor
{
    private const BEGIN = '-----BEGIN SSH SIGNATURE-----';
    private const END = '-----END SSH SIGNATURE-----';

    /** Wrap the binary blob in SSHSIG armor, base64 line-wrapped at 70 (the OpenSSH width). */
    public static function encode(string $blob): string
    {
        return self::BEGIN . "\n" . chunk_split(base64_encode($blob), 70, "\n") . self::END . "\n";
    }

    public static function decode(string $armored): string
    {
        $begin = strpos($armored, self::BEGIN);

        if ($begin === false) {
            throw new InvalidSignatureException('Missing "-----BEGIN SSH SIGNATURE-----" marker.');
        }
        $bodyStart = $begin + strlen(self::BEGIN);
        $end = strpos($armored, self::END, $bodyStart);

        if ($end === false) {
            throw new InvalidSignatureException('Missing "-----END SSH SIGNATURE-----" marker.');
        }
        $body = (string) preg_replace('/\s+/', '', substr($armored, $bodyStart, $end - $bodyStart));
        $blob = base64_decode($body, true);

        if ($blob === false || $blob === '') {
            throw new InvalidSignatureException('SSH signature armor is not valid base64.');
        }

        return $blob;
    }
}
