<?php

declare(strict_types=1);

namespace K2gl\Sshsig\Tests;

use K2gl\Sshsig\AllowedSigners;
use K2gl\Sshsig\Ed25519SigningKey;
use K2gl\Sshsig\Exception\InvalidSignatureException;
use K2gl\Sshsig\Internal\Armor;
use K2gl\Sshsig\Internal\Der;
use K2gl\Sshsig\Internal\SshWriter;
use K2gl\Sshsig\Internal\Tosign;
use K2gl\Sshsig\OpensslSigningKey;
use K2gl\Sshsig\SigningKey;
use K2gl\Sshsig\SshPublicKey;
use K2gl\Sshsig\SshsigSigner;
use K2gl\Sshsig\SshsigVerifier;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use OpenSSLAsymmetricKey;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(SshsigSigner::class)]
#[CoversClass(Ed25519SigningKey::class)]
#[CoversClass(OpensslSigningKey::class)]
#[CoversClass(Tosign::class)]
#[CoversClass(Der::class)]
#[CoversClass(SshWriter::class)]
#[CoversClass(Armor::class)]
final class SshsigSignerTest extends TestCase
{
    private const ID = 'alice@example.com';
    private const NS = 'file';
    private const MESSAGE = "k2gl/sshsig signing round-trip\n";

    /** @return iterable<string, array{SigningKey, string, string}> */
    public static function signers(): iterable
    {
        $ed = sodium_crypto_sign_keypair();
        yield 'ed25519' => [new Ed25519SigningKey(sodium_crypto_sign_secretkey($ed)), 'ssh-ed25519', 'ssh-ed25519'];
        yield 'rsa' => [OpensslSigningKey::fromKey(self::opensslKey(OPENSSL_KEYTYPE_RSA)), 'rsa-sha2-512', 'rsa-sha2-256'];
        yield 'ecdsa nistp256' => [OpensslSigningKey::fromKey(self::opensslKey(OPENSSL_KEYTYPE_EC, 'prime256v1')), 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp256'];
        yield 'ecdsa nistp384' => [OpensslSigningKey::fromKey(self::opensslKey(OPENSSL_KEYTYPE_EC, 'secp384r1')), 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp384'];
        yield 'ecdsa nistp521' => [OpensslSigningKey::fromKey(self::opensslKey(OPENSSL_KEYTYPE_EC, 'secp521r1')), 'ecdsa-sha2-nistp521', 'ecdsa-sha2-nistp521'];
    }

    #[DataProvider('signers')]
    public function testSignsAndVerifiesWithDefaultHash(SigningKey $key, string $sha512Algorithm, string $sha256Algorithm): void
    {
        $signature = (new SshsigSigner($key))->sign(self::MESSAGE, self::NS);

        $result = $this->verify($key, $signature);
        fact($result->namespace)->is(self::NS);

        $parsed = (new SshsigVerifier)->checkNoValidate(self::MESSAGE, $signature, self::NS);
        fact($parsed->signatureAlgorithm)->is($sha512Algorithm);
    }

    #[DataProvider('signers')]
    public function testSignsWithSha256(SigningKey $key, string $sha512Algorithm, string $sha256Algorithm): void
    {
        $signature = (new SshsigSigner($key))->sign(self::MESSAGE, self::NS, 'sha256');

        $parsed = (new SshsigVerifier)->checkNoValidate(self::MESSAGE, $signature, self::NS);
        fact($parsed->signatureAlgorithm)->is($sha256Algorithm);
        fact($parsed->hashAlgorithm)->is('sha256');

        $result = $this->verify($key, $signature);
        fact($result->identity)->is(self::ID);
    }

    #[DataProvider('signers')]
    public function testOpenSshVerifiesPhpSignature(SigningKey $key, string $sha512Algorithm, string $sha256Algorithm): void
    {
        if (! self::sshKeygenAvailable()) {
            self::markTestSkipped('ssh-keygen is not available.');
        }
        $signer = new SshsigSigner($key);
        $signature = $signer->sign(self::MESSAGE, self::NS);

        fact($this->sshKeygenVerifies($signer->publicKey(), $signature, self::MESSAGE))->true();
    }

    public function testRejectsEmptyNamespace(): void
    {
        // arrange
        $key = new Ed25519SigningKey(sodium_crypto_sign_secretkey(sodium_crypto_sign_keypair()));

        // act + assert
        fact(static fn () => (new SshsigSigner($key))->sign(self::MESSAGE, ''))->throws(InvalidSignatureException::class);
    }

    private function verify(SigningKey $key, string $signature): \K2gl\Sshsig\VerifiedSignature
    {
        $public = $key->publicKey();

        return (new SshsigVerifier)->verify(
            message: self::MESSAGE,
            armoredSignature: $signature,
            allowedSigners: AllowedSigners::fromString(self::allowedLine($public)),
            identity: self::ID,
            namespace: self::NS,
        );
    }

    private function sshKeygenVerifies(SshPublicKey $public, string $signature, string $message): bool
    {
        $dir = sys_get_temp_dir() . '/sshsig-' . bin2hex(random_bytes(6));
        mkdir($dir);
        file_put_contents($dir . '/message', $message);
        file_put_contents($dir . '/sig', $signature);
        file_put_contents($dir . '/allowed', self::allowedLine($public) . "\n");

        $command = sprintf(
            'ssh-keygen -Y verify -f %s -I %s -n %s -s %s < %s 2>/dev/null',
            escapeshellarg($dir . '/allowed'),
            escapeshellarg(self::ID),
            escapeshellarg(self::NS),
            escapeshellarg($dir . '/sig'),
            escapeshellarg($dir . '/message'),
        );
        exec($command, $output, $code);

        array_map('unlink', glob($dir . '/*') ?: []);
        rmdir($dir);

        return $code === 0;
    }

    private static function allowedLine(SshPublicKey $public): string
    {
        return self::ID . ' ' . $public->type . ' ' . base64_encode($public->blob);
    }

    private static function sshKeygenAvailable(): bool
    {
        exec('command -v ssh-keygen', $output, $code);

        return $code === 0;
    }

    private static function opensslKey(int $type, string $curve = ''): OpenSSLAsymmetricKey
    {
        $config = $type === OPENSSL_KEYTYPE_EC
            ? ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $curve]
            : ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048];
        $key = openssl_pkey_new($config);
        fact($key !== false)->true();

        return $key;
    }
}
