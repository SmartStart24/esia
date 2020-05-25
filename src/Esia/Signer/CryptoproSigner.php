<?php

namespace Esia\Signer;

use Esia\Signer\Exceptions\SignFailException;
use Psr\Log\LoggerAwareTrait;

class CryptoproSigner extends AbstractCryptoproSigner implements SignerInterface
{
    use LoggerAwareTrait;

    /**
     * @param string $message
     * @return string
     * @throws SignFailException
     */

    public function sign(string $message): string
    {
        $this->checkFilesExists();

        // random unique directories for sign
        $messageFile = $this->tmpPath . DIRECTORY_SEPARATOR . $this->getRandomString();
        $signFile = $this->tmpPath . DIRECTORY_SEPARATOR . $this->getRandomString();
        file_put_contents($messageFile, $message);

        $passwordRecord = is_null($this->password) ? '' : (' -pin ' . escapeshellarg($this->password) . ' ');

        $command = escapeshellarg($this->cryptcpUtilityPath) . ' -sign -der ' .
            '-issuer -' . escapeshellarg($this->store) .
            ' -thumbprint ' . escapeshellarg($this->thumbprint) . ' ' .
            $passwordRecord .
            escapeshellarg($messageFile) . ' ' .
            escapeshellarg($signFile);

        $result = exec($command);

        if ('[ErrorCode: 0x00000000]' !== $result) {
            throw new SignFailException('Signature message failed: ' . $result);
        }

        $signed = file_get_contents($signFile);
        if ($signed === false) {
            $message = sprintf('cannot read %s file', $signFile);
            $this->logger->error($message);
            throw new SignFailException($message);
        }
        $sign = $this->urlSafe(base64_encode($signed));

        unlink($signFile);
        unlink($messageFile);

        return $sign;
    }
}
