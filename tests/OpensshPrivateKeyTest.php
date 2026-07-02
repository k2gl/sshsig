<?php

declare(strict_types=1);

namespace K2gl\Sshsig\Tests;

use K2gl\Sshsig\Ed25519SigningKey;
use K2gl\Sshsig\Exception\SigningException;
use K2gl\Sshsig\Exception\UnsupportedAlgorithmException;
use K2gl\Sshsig\Internal\SshWriter;
use K2gl\Sshsig\OpensshPrivateKey;
use K2gl\Sshsig\SshPublicKey;
use K2gl\Sshsig\SshsigSigner;
use K2gl\Sshsig\SshsigVerifier;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(OpensshPrivateKey::class)]
final class OpensshPrivateKeyTest extends TestCase
{
    public function testLoadsUnencryptedEd25519Container(): void
    {
        $pair = sodium_crypto_sign_keypair();
        $pk = sodium_crypto_sign_publickey($pair);
        $sk = sodium_crypto_sign_secretkey($pair);

        $key = OpensshPrivateKey::fromString(self::armor(self::container('none', 'ssh-ed25519', $pk, $sk)));

        fact($key->publicKey()->equals((new Ed25519SigningKey($sk))->publicKey()))->true();

        $signature = (new SshsigSigner($key))->sign("hi\n", 'file');
        $result = (new SshsigVerifier)->checkNoValidate("hi\n", $signature, 'file');
        fact($result->signatureAlgorithm)->is('ssh-ed25519');
    }

    public function testFromFileLoadsAndFromFileMissingThrows(): void
    {
        $pair = sodium_crypto_sign_keypair();
        $path = sys_get_temp_dir() . '/sshsig-openssh-key-' . bin2hex(random_bytes(6));
        file_put_contents($path, self::armor(self::container(
            'none',
            'ssh-ed25519',
            sodium_crypto_sign_publickey($pair),
            sodium_crypto_sign_secretkey($pair),
        )));

        $key = OpensshPrivateKey::fromFile($path);
        unlink($path);
        fact($key)->instanceOf(Ed25519SigningKey::class);

        $this->expectException(SigningException::class);
        OpensshPrivateKey::fromFile($path);
    }

    public function testRejectsMissingArmorMarkers(): void
    {
        $this->expectException(SigningException::class);
        OpensshPrivateKey::fromString("not a key\n");
    }

    public function testRejectsWrongMagic(): void
    {
        $blob = "not-openssh-key\0" . random_bytes(16);

        $this->expectException(SigningException::class);
        OpensshPrivateKey::fromString(self::armor($blob));
    }

    public function testRejectsEncryptedContainer(): void
    {
        $pair = sodium_crypto_sign_keypair();
        $container = self::container(
            'aes256-ctr',
            'ssh-ed25519',
            sodium_crypto_sign_publickey($pair),
            sodium_crypto_sign_secretkey($pair),
        );

        $this->expectException(UnsupportedAlgorithmException::class);
        OpensshPrivateKey::fromString(self::armor($container));
    }

    public function testRejectsMoreThanOneKey(): void
    {
        $pair = sodium_crypto_sign_keypair();
        $pk = sodium_crypto_sign_publickey($pair);
        $sk = sodium_crypto_sign_secretkey($pair);

        $writer = (new SshWriter)
            ->putBytes(self::MAGIC)
            ->putString('none')
            ->putString('none')
            ->putString('')
            ->putBytes(pack('N', 2))
            ->putString(self::publicKeyBlob($pk))
            ->putString(self::publicKeyBlob($pk))
            ->putString(self::privateSection('ssh-ed25519', $pk, $sk));

        $this->expectException(UnsupportedAlgorithmException::class);
        OpensshPrivateKey::fromString(self::armor($writer->bytes()));
    }

    public function testRejectsUnsupportedKeyType(): void
    {
        $checkint = random_bytes(4);
        $private = (new SshWriter)
            ->putBytes($checkint)
            ->putBytes($checkint)
            ->putString('ssh-rsa')
            ->bytes();

        $writer = (new SshWriter)
            ->putBytes(self::MAGIC)
            ->putString('none')
            ->putString('none')
            ->putString('')
            ->putBytes(pack('N', 1))
            ->putString('dummy public key blob')
            ->putString($private);

        $this->expectException(UnsupportedAlgorithmException::class);
        OpensshPrivateKey::fromString(self::armor($writer->bytes()));
    }

    public function testRejectsChecksumMismatch(): void
    {
        $pair = sodium_crypto_sign_keypair();
        $pk = sodium_crypto_sign_publickey($pair);
        $sk = sodium_crypto_sign_secretkey($pair);

        $private = (new SshWriter)
            ->putBytes(pack('N', 1))
            ->putBytes(pack('N', 2)) // checkint2 != checkint1
            ->putString('ssh-ed25519')
            ->putString($pk)
            ->putString($sk)
            ->putString('')
            ->putBytes("\x01")
            ->bytes();

        $writer = (new SshWriter)
            ->putBytes(self::MAGIC)
            ->putString('none')
            ->putString('none')
            ->putString('')
            ->putBytes(pack('N', 1))
            ->putString(self::publicKeyBlob($pk))
            ->putString($private);

        $this->expectException(SigningException::class);
        OpensshPrivateKey::fromString(self::armor($writer->bytes()));
    }

    public function testRejectsInvalidPadding(): void
    {
        $pair = sodium_crypto_sign_keypair();
        $pk = sodium_crypto_sign_publickey($pair);
        $sk = sodium_crypto_sign_secretkey($pair);
        $checkint = random_bytes(4);

        $private = (new SshWriter)
            ->putBytes($checkint)
            ->putBytes($checkint)
            ->putString('ssh-ed25519')
            ->putString($pk)
            ->putString($sk)
            ->putString('')
            ->putBytes("\x02") // padding must start at 1
            ->bytes();

        $writer = (new SshWriter)
            ->putBytes(self::MAGIC)
            ->putString('none')
            ->putString('none')
            ->putString('')
            ->putBytes(pack('N', 1))
            ->putString(self::publicKeyBlob($pk))
            ->putString($private);

        $this->expectException(SigningException::class);
        OpensshPrivateKey::fromString(self::armor($writer->bytes()));
    }

    public function testRealSshKeygenUnencryptedKeyRoundTrips(): void
    {
        if (! self::sshKeygenAvailable()) {
            self::markTestSkipped('ssh-keygen is not available.');
        }
        $dir = self::sshKeygenGenerate('');

        $key = OpensshPrivateKey::fromFile($dir . '/id_ed25519');
        $expected = SshPublicKey::fromOpensshLine(trim((string) file_get_contents($dir . '/id_ed25519.pub')));
        fact($key->publicKey()->equals($expected))->true();

        $signer = new SshsigSigner($key);
        $signature = $signer->sign("k2gl/sshsig openssh-key-v1 fixture\n", 'file');
        fact(self::sshKeygenVerifies($dir, $signer->publicKey(), $signature, "k2gl/sshsig openssh-key-v1 fixture\n"))->true();

        self::cleanupDir($dir);
    }

    public function testRealSshKeygenEncryptedKeyIsRejected(): void
    {
        if (! self::sshKeygenAvailable()) {
            self::markTestSkipped('ssh-keygen is not available.');
        }
        $dir = self::sshKeygenGenerate('correct horse battery staple');

        $this->expectException(UnsupportedAlgorithmException::class);

        try {
            OpensshPrivateKey::fromFile($dir . '/id_ed25519');
        } finally {
            self::cleanupDir($dir);
        }
    }

    private const MAGIC = "openssh-key-v1\0";

    private static function container(string $cipherName, string $keyType, string $pk, string $sk): string
    {
        return (new SshWriter)
            ->putBytes(self::MAGIC)
            ->putString($cipherName)
            ->putString($cipherName === 'none' ? 'none' : 'bcrypt')
            ->putString('')
            ->putBytes(pack('N', 1))
            ->putString(self::publicKeyBlob($pk))
            ->putString(self::privateSection($keyType, $pk, $sk))
            ->bytes();
    }

    private static function privateSection(string $keyType, string $pk, string $sk): string
    {
        $checkint = random_bytes(4);

        return (new SshWriter)
            ->putBytes($checkint)
            ->putBytes($checkint)
            ->putString($keyType)
            ->putString($pk)
            ->putString($sk)
            ->putString('k2gl/sshsig test fixture')
            ->putBytes("\x01")
            ->bytes();
    }

    private static function publicKeyBlob(string $pk): string
    {
        return (new SshWriter)->putString('ssh-ed25519')->putString($pk)->bytes();
    }

    private static function armor(string $blob): string
    {
        return "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            . chunk_split(base64_encode($blob), 70, "\n")
            . "-----END OPENSSH PRIVATE KEY-----\n";
    }

    private static function sshKeygenAvailable(): bool
    {
        exec('command -v ssh-keygen', $output, $code);

        return $code === 0;
    }

    private static function sshKeygenGenerate(string $passphrase): string
    {
        $dir = sys_get_temp_dir() . '/sshsig-openssh-key-' . bin2hex(random_bytes(6));
        mkdir($dir);
        $command = sprintf(
            'ssh-keygen -t ed25519 -N %s -C fixture -f %s -q',
            escapeshellarg($passphrase),
            escapeshellarg($dir . '/id_ed25519'),
        );
        exec($command, $output, $code);
        fact($code)->is(0);

        return $dir;
    }

    private static function sshKeygenVerifies(string $dir, SshPublicKey $public, string $signature, string $message): bool
    {
        file_put_contents($dir . '/message', $message);
        file_put_contents($dir . '/sig', $signature);
        file_put_contents($dir . '/allowed', 'fixture ' . $public->type . ' ' . base64_encode($public->blob) . "\n");

        $command = sprintf(
            'ssh-keygen -Y verify -f %s -I fixture -n file -s %s < %s 2>/dev/null',
            escapeshellarg($dir . '/allowed'),
            escapeshellarg($dir . '/sig'),
            escapeshellarg($dir . '/message'),
        );
        exec($command, $output, $code);

        return $code === 0;
    }

    private static function cleanupDir(string $dir): void
    {
        array_map('unlink', glob($dir . '/*') ?: []);
        rmdir($dir);
    }
}
