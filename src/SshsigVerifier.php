<?php

declare(strict_types=1);

namespace K2gl\Sshsig;

use DateTimeImmutable;
use K2gl\Sshsig\Exception\SignatureVerificationFailed;
use K2gl\Sshsig\Exception\SignerNotAllowedException;
use K2gl\Sshsig\Exception\UnsupportedAlgorithmException;
use K2gl\Sshsig\Internal\SignaturePrimitive;

/**
 * Verifies OpenSSH SSHSIG signatures (the `ssh-keygen -Y verify` /
 * `-Y check-novalidate` operations). Fail-closed: any malformed input,
 * unsupported algorithm, failed cryptographic check, or unauthorized signer
 * throws an {@see \K2gl\Sshsig\Exception\SshsigException}; nothing is ever
 * silently treated as verified.
 */
final class SshsigVerifier
{
    /** Signature algorithms accepted for verification (legacy SHA-1 "ssh-rsa" is refused). */
    private const SUPPORTED_ALGORITHMS = [
        'ssh-ed25519',
        'rsa-sha2-256',
        'rsa-sha2-512',
        'ecdsa-sha2-nistp256',
        'ecdsa-sha2-nistp384',
        'ecdsa-sha2-nistp521',
    ];

    /**
     * Full `ssh-keygen -Y verify`: cryptographically verify the signature over
     * the message, then authorize the signer against the allowed_signers file
     * for the given identity and namespace.
     *
     * @throws \K2gl\Sshsig\Exception\SshsigException when verification fails
     */
    public function verify(
        string $message,
        string $armoredSignature,
        AllowedSigners $allowedSigners,
        string $identity,
        string $namespace,
        ?DateTimeImmutable $verifyTime = null,
    ): VerifiedSignature {
        $signature = $this->cryptographicallyVerify($message, $armoredSignature, $namespace);
        $match = $allowedSigners->findMatch(
            identity: $identity,
            namespace: $namespace,
            key: $signature->publicKey,
            time: $verifyTime ?? new DateTimeImmutable,
        );

        if ($match === null) {
            throw new SignerNotAllowedException(
                sprintf('No allowed_signers entry authorizes "%s" for namespace "%s".', $identity, $namespace)
            );
        }

        return new VerifiedSignature(
            identity: $identity,
            namespace: $namespace,
            publicKey: $signature->publicKey,
            principals: $match->principals,
        );
    }

    /**
     * `ssh-keygen -Y check-novalidate`: verify the signature is structurally
     * sound and cryptographically valid under its own embedded key, without
     * authorizing the signer. Returns the parsed signature for inspection.
     *
     * @throws \K2gl\Sshsig\Exception\SshsigException when verification fails
     */
    public function checkNoValidate(string $message, string $armoredSignature, string $namespace): SshSignature
    {
        return $this->cryptographicallyVerify($message, $armoredSignature, $namespace);
    }

    private function cryptographicallyVerify(string $message, string $armoredSignature, string $namespace): SshSignature
    {
        $signature = SshSignature::fromArmored($armoredSignature);

        if ($signature->namespace !== $namespace) {
            throw new SignatureVerificationFailed(
                sprintf('Signature namespace "%s" does not match the expected "%s".', $signature->namespace, $namespace)
            );
        }

        if (! in_array($signature->signatureAlgorithm, self::SUPPORTED_ALGORITHMS, true)) {
            throw new UnsupportedAlgorithmException(
                sprintf('Unsupported SSHSIG signature algorithm "%s".', $signature->signatureAlgorithm)
            );
        }
        $verified = SignaturePrimitive::verify(
            publicKeyBlob: $signature->publicKey->blob,
            signatureAlgorithm: $signature->signatureAlgorithm,
            signedData: $signature->signedData($message),
            signature: $signature->signature,
        );

        if (! $verified) {
            throw new SignatureVerificationFailed('The signature does not match the message under the signer key.');
        }

        return $signature;
    }
}
