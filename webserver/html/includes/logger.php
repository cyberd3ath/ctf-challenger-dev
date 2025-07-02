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

?>
