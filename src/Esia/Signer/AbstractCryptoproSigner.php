<?php

namespace Esia\Signer;

use Esia\Signer\Exceptions\CannotReadCryptcpUtilityException;
use Esia\Signer\Exceptions\NoSuchCryptcpUtilityException;
use Esia\Signer\Exceptions\NoSuchTmpDirException;
use Esia\Signer\Exceptions\SignFailException;

abstract class AbstractCryptoproSigner
{
    /**
     * Cryptcp utility path.
     *
     * @var string
     */
    protected $cryptcpUtilityPath;

    /**
     * Cryptopro store.
     *
     * @var string
     */
    protected $store;

    /**
     * Cryptopro cert's thumbprint.
     *
     * @var string
     */
    protected $thumbprint;

    /**
     * Cryptopro container password.
     *
     * @var string|null
     */
    protected $password;

    /**
     * AbstractCryptoproSigner constructor.
     * @param string $thumbprint
     * @param string|null $cryptcpUtilityPath
     * @param string|null $store
     * @param string|null $password
     * @param string|null $tmpPath
     */
    public function __construct(
        string $thumbprint,
        string $store = 'uMy',
        string $password = null,
        string $cryptcpUtilityPath = '/opt/cprocsp/bin/amd64/cryptcp',
        string $tmpPath = null
    ) {
        $this->cryptcpUtilityPath = $cryptcpUtilityPath;
        $this->thumbprint = $thumbprint;
        $this->password = $password;
        $this->store = $store;
        $this->tmpPath = $tmpPath ?? sys_get_temp_dir();
    }

    /**
     * Temporary directory for message signing (must me writable)
     *
     * @var string
     */
    protected $tmpPath;

    /**
     * @throws SignFailException
     */
    protected function checkFilesExists(): void
    {
        if (!file_exists($this->cryptcpUtilityPath)) {
            throw new NoSuchCryptcpUtilityException('Cryptcp utility does not exist');
        }
        if (!is_readable($this->cryptcpUtilityPath)) {
            throw new CannotReadCryptcpUtilityException('Cannot read cryptcp utility');
        }
        if (!file_exists($this->tmpPath)) {
            throw new NoSuchTmpDirException('Temporary folder is not found');
        }
        if (!is_writable($this->tmpPath)) {
            throw new NoSuchTmpDirException('Temporary folder is not writable');
        }
    }

    /**
     * Generate random unique string
     *
     * @return string
     */
    protected function getRandomString(): string
    {
        return md5(uniqid(mt_rand(), true));
    }

    /**
     * Url safe for base64
     *
     * @param string $string
     * @return string
     */
    protected function urlSafe($string): string
    {
        return rtrim(strtr(trim($string), '+/', '-_'), '=');
    }
}
