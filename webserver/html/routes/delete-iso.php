<?php
require_once '../includes/auth.php';
require_once '../includes/response.php';
require_once '../includes/logger.php';
require_once '../includes/curlHelper.php';

$isoName = filter_input(INPUT_POST, 'iso_name', FILTER_SANITIZE_SPECIAL_CHARS);
$node = filter_input(INPUT_POST, 'node', FILTER_SANITIZE_SPECIAL_CHARS);
$storage = filter_input(INPUT_POST, 'storage', FILTER_SANITIZE_SPECIAL_CHARS);

if (empty(trim($isoName)) || empty(trim($node)) || empty(trim($storage))) {
    logError("Invalid request parameters: isoName=" . var_export($isoName, true) . ", node=" . var_export($node, true) . ", storage=" . var_export($storage, true));
    jsonResponse(false, "Invalid or missing parameters.", null, 400);
    exit;
}

$endpoint = "/api2/json/nodes/$node/storage/$storage/content/$storage:iso/$isoName";

$authHeaders = getAuthHeaders();
$result = makeCurlRequest($endpoint, 'DELETE', $authHeaders, null);

if (!$result) {
    logError("cURL error while deleting iso $isoName on node $node with storage $storage.");
    jsonResponse(false, "Service temporarily unavailable.", null, 503);
    exit;
}
$response = $result['response'];
$httpCode = $result['http_code'];

$responseData = json_decode($response, true);

if (!$responseData || $httpCode !== 200) {
    logError("Unexpected response from Proxmox: HTTP $httpCode, Response: " . json_encode($responseData));
    jsonResponse(false, "An unexpected error occurred.", null, 500);
    exit;
}

jsonResponse(true, "Iso is getting deleted.", null);
logInfo("ISO=$isoName is getting deleted.");
?>
