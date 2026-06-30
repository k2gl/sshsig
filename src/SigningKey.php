<?php

declare(strict_types=1);

namespace K2gl\Sshsig;

/**
 * A private key able to produce SSHSIG signatures. Implementations expose the
 * matching public key (embedded in the signature) and sign the "to be signed"
 * blob. Custom implementations (e.g. HSM- or agent-backed) can plug in here.
 */
interface SigningKey
{
    public function publicKey(): SshPublicKey;

    /**
     * Sign the SSHSIG "to be signed" blob.
     *
     * @return array{0: string, 1: string} the SSH signature algorithm and the
     *     signature bytes for the inner signature blob (for ECDSA the bytes are
     *     the SSH-encoded `string r || string s`)
     */
    public function signTosign(string $tosign, string $hashAlgorithm): array;
}
