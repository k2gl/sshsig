<?php

declare(strict_types=1);

namespace K2gl\Sshsig\Tests;

use DateTimeImmutable;
use K2gl\Sshsig\AllowedSigner;
use K2gl\Sshsig\AllowedSigners;
use K2gl\Sshsig\Exception\InvalidSignatureException;
use K2gl\Sshsig\Exception\SignerNotAllowedException;
use K2gl\Sshsig\Internal\Pattern;
use K2gl\Sshsig\SshPublicKey;
use K2gl\Sshsig\SshsigVerifier;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(AllowedSigners::class)]
#[CoversClass(AllowedSigner::class)]
#[CoversClass(Pattern::class)]
#[CoversClass(SshPublicKey::class)]
final class AllowedSignersTest extends TestCase
{
    private const ID = 'alice@example.com';
    private const NS = 'file';

    public function testAuthorizesWithNamespaceWildcard(): void
    {
        $result = $this->verify($this->line(self::ID, 'namespaces="git,fi*"'));

        fact($result->principals)->is(self::ID);
    }

    public function testRejectsNamespaceOutsideRestriction(): void
    {
        $this->expectException(SignerNotAllowedException::class);

        $this->verify($this->line(self::ID, 'namespaces="git,mail"'));
    }

    public function testAuthorizesWithinValidityWindow(): void
    {
        $line = $this->line(self::ID, 'valid-after="20000101Z",valid-before="20990101Z"');
        $result = $this->verify($line, new DateTimeImmutable('2026-06-30T12:00:00Z'));

        fact($result->namespace)->is(self::NS);
    }

    public function testRejectsExpiredKey(): void
    {
        $this->expectException(SignerNotAllowedException::class);

        $this->verify($this->line(self::ID, 'valid-before="19700101Z"'), new DateTimeImmutable('2026-06-30T12:00:00Z'));
    }

    public function testRejectsNotYetValidKey(): void
    {
        $this->expectException(SignerNotAllowedException::class);

        $this->verify($this->line(self::ID, 'valid-after="20990101Z"'), new DateTimeImmutable('2026-06-30T12:00:00Z'));
    }

    public function testAuthorizesPrincipalWildcard(): void
    {
        $result = $this->verify($this->line('*@example.com', ''));

        fact($result->identity)->is(self::ID);
    }

    public function testRejectsNegatedPrincipal(): void
    {
        $this->expectException(SignerNotAllowedException::class);

        $this->verify($this->line('!alice@example.com,*@example.com', ''));
    }

    public function testSkipsCertAuthorityEntries(): void
    {
        $this->expectException(SignerNotAllowedException::class);

        $this->verify($this->line(self::ID, 'cert-authority'));
    }

    public function testParsesCommentsAndBlankLines(): void
    {
        $contents = "# a comment\n\n" . $this->line(self::ID, '') . "\n";
        $signers = AllowedSigners::fromString($contents);

        fact(count($signers->all()))->is(1);
    }

    public function testRejectsMalformedLine(): void
    {
        $this->expectException(InvalidSignatureException::class);

        AllowedSigners::fromString('only-one-token');
    }

    private function verify(string $allowedSigners, ?DateTimeImmutable $time = null): \K2gl\Sshsig\VerifiedSignature
    {
        return (new SshsigVerifier)->verify(
            message: self::fixture('message.txt'),
            armoredSignature: self::fixture('ed25519.sig'),
            allowedSigners: AllowedSigners::fromString($allowedSigners),
            identity: self::ID,
            namespace: self::NS,
            verifyTime: $time,
        );
    }

    private function line(string $principals, string $options): string
    {
        $parts = explode(' ', trim(self::fixture('ed25519.pub')));
        $key = $parts[0] . ' ' . $parts[1];

        return rtrim($principals . ' ' . ($options === '' ? '' : $options . ' ') . $key);
    }

    private static function fixture(string $name): string
    {
        return (string) file_get_contents(__DIR__ . '/fixtures/sshsig/' . $name);
    }
}
