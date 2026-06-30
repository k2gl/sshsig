<?php

declare(strict_types=1);

namespace K2gl\Sshsig\Exception;

use RuntimeException;

/**
 * The signature is cryptographically valid but the signer is not authorized:
 * no allowed_signers entry matches the identity, namespace, validity window,
 * and public key being verified.
 */
final class SignerNotAllowedException extends RuntimeException implements SshsigException {}
