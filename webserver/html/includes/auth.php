<?php
function getAuthHeaders($contentType = null)
{
    require_once __DIR__ . '/../vendor/autoload.php';
    require_once __DIR__ . '/logger.php';

    $dotenv = Dotenv\Dotenv::createImmutable("/var/www");
    $dotenv->load();

    $username = $_ENV['PROXMOX_USER'];
    $password = $_ENV['PROXMOX_PASSWORD'];
    $base_url = $_ENV['PROXMOX_HOSTNAME'];
    if (isset($_ENV['PROXMOX_PORT'])) {
        $base_url .= ":" . $_ENV['PROXMOX_PORT'];
    }

    $url = 'https://' . $base_url . "/api2/json/access/ticket";
    $post_params = json_encode([
        'username' => $username,
        'password' => $password
    ]);

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $post_params);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "Content-Type: application/json"
    ]);

    $response = curl_exec($ch);
    if (curl_errno($ch)) {
        logError("cURL error while authenticating to Proxmox");
        curl_close($ch);
        exit;
    }

    $decodedResponse = json_decode($response, true);
    curl_close($ch);

    if (!isset($decodedResponse['data'])) {
        logError("Proxmox Authentication Error");
        exit;
    }

    $cookie = "PVEAuthCookie=" . $decodedResponse['data']['ticket'];
    $csrfToken = $decodedResponse['data']['CSRFPreventionToken'];

    $headers = [
        "Cookie: $cookie",
        "CSRFPreventionToken: $csrfToken"
    ];

    if ($contentType !== null) {
        $headers[] = "Content-Type: $contentType";
    }

    return $headers;
}

function getBackendHeaders($contentType = 'application/json')
{
    $dotenv = Dotenv\Dotenv::createImmutable("/var/www");
    $dotenv->load();

    $BACKEND_AUTHENTICATION_TOKEN = $_ENV['BACKEND_AUTHENTICATION_TOKEN'] ?? null;

    $headers = [
        'Content-Type: ' . $contentType,
        'Authentication-Token: ' . $BACKEND_AUTHENTICATION_TOKEN
    ];

    return $headers;
}
