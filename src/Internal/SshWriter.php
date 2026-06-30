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

    public function bytes(): string
    {
        return $this->buffer;
    }
}
