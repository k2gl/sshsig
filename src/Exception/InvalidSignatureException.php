<?php

declare(strict_types=1);

namespace K2gl\Sshsig\Exception;

use RuntimeException;

/**
 * The armored signature, its SSH-wire blob, or an allowed_signers entry is
 * malformed: bad armor, truncated or trailing bytes, an unexpected MAGIC
 * preamble, a version other than 1, or an empty namespace.
 */
final class InvalidSignatureException extends RuntimeException implements SshsigException {}
