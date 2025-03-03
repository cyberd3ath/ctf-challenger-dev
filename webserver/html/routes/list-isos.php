<?php
require_once '../includes/auth.php';
require_once '../includes/response.php';
require_once '../includes/logger.php';
require_once '../includes/curlHelper.php';

$node = filter_input(INPUT_GET, 'node', FILTER_SANITIZE_SPECIAL_CHARS);

if (empty(trim($node))) {
    logError("Invalid request parameters: node=" . var_export($node, true));
    jsonResponse(false, "Invalid or missing parameters.", null, 400);
    exit;
}

$endpoint = "/api2/json/nodes/$node/storage/local/content?content=iso";

$authHeaders = getAuthHeaders();
$result = makeCurlRequest($endpoint, 'GET', $authHeaders, null);

if (!$result) {
    logError("cURL error while listing isos on node $node.");
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

jsonResponse(true, "Iso listing initiated.", $responseData);
logInfo("Iso listing initiated.");
?>
