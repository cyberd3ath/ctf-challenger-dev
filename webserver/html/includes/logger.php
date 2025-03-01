<?php
function logError($message) {
    $logFile = __DIR__ . '/../logs/api_errors.log';
    $timestamp = date("Y-m-d H:i:s");
    $formattedMessage = "[$timestamp] ERROR: $message\n";

    file_put_contents($logFile, $formattedMessage, FILE_APPEND);
}

function logInfo($message) {
    $logFile = __DIR__ . '/../logs/api_info.log';
    $timestamp = date("Y-m-d H:i:s");
    $formattedMessage = "[$timestamp] INFO: $message\n";

    file_put_contents($logFile, $formattedMessage, FILE_APPEND);
}
?>
