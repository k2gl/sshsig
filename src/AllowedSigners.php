<?php

declare(strict_types=1);

namespace K2gl\Sshsig;

use DateTimeImmutable;
use DateTimeZone;
use K2gl\Sshsig\Exception\InvalidSignatureException;
use K2gl\Sshsig\Internal\Pattern;

/**
 * A parsed OpenSSH allowed_signers file (see ssh-keygen(1) "ALLOWED SIGNERS").
 * Authorizes a verified signature by matching its identity, namespace, validity
 * window, and public key against the file's entries.
 *
 * Certificate-authority entries are parsed but not used to authorize plain-key
 * signatures (certificate chains are out of scope for now).
 */
final class AllowedSigners
{
    /** @param list<AllowedSigner> $signers */
    public function __construct(private readonly array $signers) {}

    public static function fromString(string $contents): self
    {
        $lines = preg_split('/\r\n|\r|\n/', $contents);
        $signers = [];

        foreach ($lines === false ? [] : $lines as $line) {
            $signer = self::parseLine($line);

            if ($signer !== null) {
                $signers[] = $signer;
            }
        }

        return new self($signers);
    }

    public static function fromFile(string $path): self
    {
        $contents = @file_get_contents($path);

        if ($contents === false) {
            throw new InvalidSignatureException(sprintf('Cannot read allowed_signers file "%s".', $path));
        }

        return self::fromString($contents);
    }

    /** @return list<AllowedSigner> */
    public function all(): array
    {
        return $this->signers;
    }

    /**
     * The first entry that authorizes this signature, or null if none does.
     */
    public function findMatch(string $identity, string $namespace, SshPublicKey $key, DateTimeImmutable $time): ?AllowedSigner
    {
        foreach ($this->signers as $signer) {
            if ($signer->certAuthority) {
                continue;
            }

            if (! Pattern::matchesList($signer->principals, $identity)) {
                continue;
            }

            if (! $signer->key->equals($key)) {
                continue;
            }

            if ($signer->namespaces !== null && ! Pattern::matchesList($signer->namespaces, $namespace)) {
                continue;
            }

            if ($signer->validAfter !== null && $time < $signer->validAfter) {
                continue;
            }

            if ($signer->validBefore !== null && $time > $signer->validBefore) {
                continue;
            }

            return $signer;
        }

        return null;
    }

    private static function parseLine(string $line): ?AllowedSigner
    {
        $line = trim($line);

        if ($line === '' || str_starts_with($line, '#')) {
            return null;
        }
        $tokens = preg_split('/\s+/', $line);

        if ($tokens === false || count($tokens) < 3) {
            throw new InvalidSignatureException('Malformed allowed_signers line.');
        }

        if (self::isKeyType($tokens[1])) {
            $options = '';
            $key = SshPublicKey::fromOpensshLine($tokens[1] . ' ' . $tokens[2]);
        } else {
            if (count($tokens) < 4) {
                throw new InvalidSignatureException('Malformed allowed_signers line: missing key.');
            }
            $options = $tokens[1];
            $key = SshPublicKey::fromOpensshLine($tokens[2] . ' ' . $tokens[3]);
        }
        [$certAuthority, $namespaces, $validAfter, $validBefore] = self::parseOptions($options);

        return new AllowedSigner(
            principals: $tokens[0],
            key: $key,
            certAuthority: $certAuthority,
            namespaces: $namespaces,
            validAfter: $validAfter,
            validBefore: $validBefore,
        );
    }

    private static function isKeyType(string $token): bool
    {
        return str_starts_with($token, 'ssh-')
            || str_starts_with($token, 'ecdsa-')
            || str_starts_with($token, 'sk-');
    }

    /**
     * @return array{0: bool, 1: ?string, 2: ?DateTimeImmutable, 3: ?DateTimeImmutable}
     */
    private static function parseOptions(string $options): array
    {
        $certAuthority = false;
        $namespaces = null;
        $validAfter = null;
        $validBefore = null;

        foreach (self::splitOptions($options) as $option) {
            if ($option === '') {
                continue;
            }
            $equals = strpos($option, '=');
            $name = strtolower($equals === false ? $option : substr($option, 0, $equals));
            $value = $equals === false ? '' : trim(substr($option, $equals + 1), '"');

            match ($name) {
                'cert-authority' => $certAuthority = true,
                'namespaces' => $namespaces = $value,
                'valid-after' => $validAfter = self::parseTimestamp($value),
                'valid-before' => $validBefore = self::parseTimestamp($value),
                default => null,
            };
        }

        return [$certAuthority, $namespaces, $validAfter, $validBefore];
    }

    /** @return list<string> */
    private static function splitOptions(string $options): array
    {
        $result = [];
        $current = '';
        $inQuotes = false;
        $length = strlen($options);

        for ($i = 0; $i < $length; $i++) {
            $char = $options[$i];

            if ($char === '"') {
                $inQuotes = ! $inQuotes;
                $current .= $char;

                continue;
            }

            if ($char === ',' && ! $inQuotes) {
                $result[] = $current;
                $current = '';

                continue;
            }
            $current .= $char;
        }

        if ($current !== '') {
            $result[] = $current;
        }

        return $result;
    }

    private static function parseTimestamp(string $value): DateTimeImmutable
    {
        $utc = str_ends_with($value, 'Z');

        if ($utc) {
            $value = substr($value, 0, -1);
        }
        $format = match (strlen($value)) {
            8 => 'Ymd',
            12 => 'YmdHi',
            14 => 'YmdHis',
            default => throw new InvalidSignatureException(sprintf('Invalid allowed_signers timestamp "%s".', $value)),
        };
        $zone = new DateTimeZone($utc ? 'UTC' : date_default_timezone_get());
        $time = DateTimeImmutable::createFromFormat('!' . $format, $value, $zone);

        if ($time === false) {
            throw new InvalidSignatureException(sprintf('Invalid allowed_signers timestamp "%s".', $value));
        }

        return $time;
    }
}
