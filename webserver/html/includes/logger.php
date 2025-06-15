<?php
function logError($message)
{
    $logFile = '/var/log/ctf-challenger/api_errors.log';
    $timestamp = date("Y-m-d H:i:s");
    $formattedMessage = "[$timestamp] ERROR: $message\n";

    file_put_contents($logFile, $formattedMessage, FILE_APPEND);
}

function logInfo($message)
{
    $logFile = '/var/log/ctf-challenger/api_info.log';
    $timestamp = date("Y-m-d H:i:s");
    $formattedMessage = "[$timestamp] INFO: $message\n";

    file_put_contents($logFile, $formattedMessage, FILE_APPEND);
}

function logDebug($message)
{
    $logFile = '/var/log/ctf-challenger/api_debug.log';
    $timestamp = date("Y-m-d H:i:s");
    $formattedMessage = "[$timestamp] DEBUG: $message\n";

    file_put_contents($logFile, $formattedMessage, FILE_APPEND);
}

function logWarning($message)
{
    $logFile = '/var/log/ctf-challenger/api_warning.log';
    $timestamp = date("Y-m-d H:i:s");
    $formattedMessage = "[$timestamp] WARNING: $message\n";

    file_put_contents($logFile, $formattedMessage, FILE_APPEND);
}

function anonymizeIp(string $ip): string
{
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return preg_replace('/\.\d+$/', '.xxx', $ip);
    }
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        return preg_replace('/:[^:]+$/', ':xxxx', $ip);
    }
    return 'invalid-ip';
}
?>
