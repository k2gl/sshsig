<?php

declare(strict_types=1);

namespace K2gl\Sshsig\Internal;

use K2gl\Sshsig\Exception\InvalidSignatureException;

/**
 * Reads the SSH wire format (RFC 4251 §5): big-endian fixed-width integers and
 * uint32-length-prefixed strings/mpints. Every read is bounds-checked and
 * throws on truncation, so malformed input can never run off the end.
 *
 * @internal
 */
final class SshReader
{
    private int $offset = 0;

    public function __construct(private readonly string $bytes) {}

    public function readByte(): int
    {
        return ord($this->readBytes(1));
    }

    public function readBytes(int $length): string
    {
        if ($length < 0 || $this->offset + $length > strlen($this->bytes)) {
            throw new InvalidSignatureException('Truncated SSH wire data.');
        }
        $value = substr($this->bytes, $this->offset, $length);
        $this->offset += $length;

        return $value;
    }

    public function readUint32(): int
    {
        $bytes = $this->readBytes(4);

        return (ord($bytes[0]) << 24) | (ord($bytes[1]) << 16) | (ord($bytes[2]) << 8) | ord($bytes[3]);
    }

    /** A uint32-length-prefixed string (also the encoding of an mpint). */
    public function readString(): string
    {
        return $this->readBytes($this->readUint32());
    }

    public function isAtEnd(): bool
    {
        return $this->offset === strlen($this->bytes);
    }

    public function assertAtEnd(): void
    {
        if (! $this->isAtEnd()) {
            throw new InvalidSignatureException('Trailing bytes after SSH wire data.');
        }
    }
}
