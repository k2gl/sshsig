<?php

declare(strict_types=1);

namespace K2gl\Sshsig\Exception;

use RuntimeException;

/**
 * The cryptographic check did not pass: the signature does not match the
 * message under the signer's public key, or the signature's namespace differs
 * from the one being verified.
 */
final class SignatureVerificationFailed extends RuntimeException implements SshsigException {}
