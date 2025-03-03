<?php
require_once '../includes/auth.php';
require_once '../includes/response.php';
require_once '../includes/logger.php';
require_once '../includes/curlHelper.php';

$endpoint = "/api2/json/cluster/resources";

$authHeaders = getAuthHeaders();
$result = makeCurlRequest($endpoint, 'GET', $authHeaders, null);

if (!$result) {
    logError("cURL error while listing ressources.");
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

jsonResponse(true, "VM ressource listing initiated.", $responseData);
logInfo("VM ressource listing initiated.");
?>
