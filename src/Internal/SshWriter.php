<?php

declare(strict_types=1);

namespace K2gl\Sshsig\Internal;

/**
 * Builds an SSH wire buffer (RFC 4251 §5): raw bytes, big-endian uint32, and
 * uint32-length-prefixed strings. Used to reconstruct the exact "to be signed"
 * blob that SSHSIG hashes and signs.
 *
 * @internal
 */
final class SshWriter
{
    private string $buffer = '';

    public function putBytes(string $bytes): self
    {
        $this->buffer .= $bytes;

        return $this;
    }

    public function putString(string $value): self
    {
        $this->buffer .= pack('N', strlen($value)) . $value;

        return $this;
    }

    /** A multiple-precision integer from an unsigned big-endian magnitude (RFC 4251 §5). */
    public function putMpint(string $magnitude): self
    {
        $value = ltrim($magnitude, "\x00");

        if ($value !== '' && (ord($value[0]) & 0x80) !== 0) {
            $value = "\x00" . $value;
        }

        return $this->putString($value);
    }

    public function bytes(): string
    {
        return $this->buffer;
    }
}
