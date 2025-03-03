<?php
require_once '../includes/auth.php';
require_once '../includes/response.php';
require_once '../includes/logger.php';
require_once '../includes/curlHelper.php';

$vmId = filter_input(INPUT_POST, 'vm_id', FILTER_VALIDATE_INT, ["options" => ["min_range" => 100]]);
$node = filter_input(INPUT_POST, 'node', FILTER_SANITIZE_SPECIAL_CHARS);

if($vmId === false || empty(trim($node))){
    logError("Invalid request parameters: vm_id=" . var_export($vmId, true) . ", node=" . var_export($node, true));
    jsonResponse(false, "Invalid or missing parameters.", null, 400);
    exit;
}

$endpoint = "/api2/json/nodes/$node/qemu/$vmId/status/stop";

$authHeaders = getAuthHeaders();
$result = makeCurlRequest($endpoint, 'POST', $authHeaders, null);

if (!$result) {
    logError("cURL error while stopping VM ID $vmId on node $node.");
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

jsonResponse(true, "VM shutdown initiated.", null);
logInfo("VM ID=$vmId shutdown initiated");
?>
