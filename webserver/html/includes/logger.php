<?php

interface ILogger
{
    public function logError($message): void;
    public function logInfo($message): void;
    public function logDebug($message): void;
    public function logWarning($message): void;
    public static function anonymizeIp(string $ip): string;
}

class Logger implements ILogger
{
    private string $errorLogFile;
    private string $infoLogFile;
    private string $debugLogFile;
    private string $warningLogFile;

    public function __construct(
        string $errorLogFile = '/var/log/ctf-challenger/api_errors.log',
        string $infoLogFile = '/var/log/ctf-challenger/api_info.log',
        string $debugLogFile = '/var/log/ctf-challenger/api_debug.log',
        string $warningLogFile = '/var/log/ctf-challenger/api_warning.log'
    )
    {
        $this->errorLogFile = $errorLogFile;
        $this->infoLogFile = $infoLogFile;
        $this->debugLogFile = $debugLogFile;
        $this->warningLogFile = $warningLogFile;
    }

    public function logError($message): void
    {
        $timestamp = date("Y-m-d H:i:s");
        $formattedMessage = "[$timestamp] ERROR: $message\n";

        file_put_contents($this->errorLogFile, $formattedMessage, FILE_APPEND);
    }
    public function logInfo($message): void
    {
        $timestamp = date("Y-m-d H:i:s");
        $formattedMessage = "[$timestamp] INFO: $message\n";

        file_put_contents($this->infoLogFile, $formattedMessage, FILE_APPEND);
    }
    public function logDebug($message): void
    {
        $timestamp = date("Y-m-d H:i:s");
        $formattedMessage = "[$timestamp] DEBUG: $message\n";

        file_put_contents($this->debugLogFile, $formattedMessage, FILE_APPEND);
    }
    public function logWarning($message): void
    {
        $timestamp = date("Y-m-d H:i:s");
        $formattedMessage = "[$timestamp] WARNING: $message\n";

        file_put_contents($this->warningLogFile, $formattedMessage, FILE_APPEND);
    }
    public static function anonymizeIp(string $ip): string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return preg_replace('/\.\d+$/', '.xxx', $ip);
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return preg_replace('/:[^:]+$/', ':xxxx', $ip);
        }
        return 'invalid-ip';
    }
}