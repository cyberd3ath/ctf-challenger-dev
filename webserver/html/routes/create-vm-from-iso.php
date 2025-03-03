<?php
require_once '../includes/auth.php';
require_once '../includes/response.php';
require_once '../includes/logger.php';
require_once '../includes/curlHelper.php';

$isoName = filter_input(INPUT_POST, 'iso_name', FILTER_SANITIZE_SPECIAL_CHARS);
$vmId = filter_input(INPUT_POST, 'vm_id', FILTER_VALIDATE_INT, ["options" => ["min_range" => 100]]);
$node = filter_input(INPUT_POST, 'node', FILTER_SANITIZE_SPECIAL_CHARS);
$vmName = filter_input(INPUT_POST,'vm_name', FILTER_SANITIZE_SPECIAL_CHARS);

if (empty(trim($isoName)) || $vmId === false || empty(trim($node)) || empty(trim($vmName))) {
    logError("Invalid request parameters: vm_id=" . var_export($vmId, true) . ", node=" . var_export($node, true) . ", iso_name=" . var_export($isoName, true) . ", name=" . var_export($vmName, true));
    jsonResponse(false, "Invalid or missing parameters.", null, 400);
    exit;
}

if (!preg_match('/\.iso$/i', $isoName)) {
    jsonResponse(false, "Invalid ISO file name.", null, 400);
    exit;
}

$endpoint = "/api2/json/nodes/$node/qemu";
$post_params = json_encode([
    'vmid' => $vmId,
    'cdrom' => $isoName,
    'name' => $vmName
]);

$authHeaders = getAuthHeaders("application/json");
$result = makeCurlRequest($endpoint, 'POST', $authHeaders, $post_params);

if (!$result) {
    logError("cURL error while creating VM ID $vmId on node $node");
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

jsonResponse(true, "VM is being created.", null);
logInfo("VM ID=$vmId created");
?>
