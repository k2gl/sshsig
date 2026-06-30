<?php

declare(strict_types=1);

namespace K2gl\Sshsig\Exception;

use Throwable;

/**
 * Marker interface for every exception thrown by this library. A thrown
 * SshsigException always means "not verified": catch this one type to treat
 * any failure (malformed input, unsupported algorithm, bad signature, or an
 * unauthorized signer) as a verification failure.
 */
interface SshsigException extends Throwable {}
