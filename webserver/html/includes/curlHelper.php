<?php
require __DIR__ . '/../vendor/autoload.php';

$dotenv = Dotenv\Dotenv::createImmutable("/var/www");
$dotenv->load();

function makeCurlRequest($endpoint, $method = 'GET', $headers = [], $postFields = null)
{
    $baseUrl = 'https://' . $_ENV['PROXMOX_HOSTNAME'];
    if (isset($_ENV['PROXMOX_PORT'])) {
        $baseUrl .= ":" . $_ENV['PROXMOX_PORT'];
    }

    $url = $baseUrl . '/' . ltrim($endpoint, '/');

    $ch = curl_init($url);
    $defaultOptions = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_HTTPHEADER => $headers
    ];

    if ($method === 'POST') {
        if ($postFields !== null) {
            $defaultOptions[CURLOPT_POST] = true;
            $defaultOptions[CURLOPT_POSTFIELDS] = $postFields;
        } else {
            $defaultOptions[CURLOPT_CUSTOMREQUEST] = 'POST';
        }
    } elseif (in_array($method, ['DELETE', 'PUT', 'GET'])) {
        $defaultOptions[CURLOPT_CUSTOMREQUEST] = $method;
    }

    curl_setopt_array($ch, $defaultOptions);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

    if ($response === false) {
        curl_close($ch);
        return false;
    }

    curl_close($ch);

    return ['response' => $response, 'http_code' => $httpCode];
}

function makeBackendRequest($endpoint, $method = 'GET', $headers = [], $postFields = null)
{
    $baseUrl = 'https://' . rtrim($_ENV['BACKEND_HOST'], '/');
    if (isset($_ENV['BACKEND_PORT'])) {
        $baseUrl .= ":" . $_ENV['BACKEND_PORT'];
    }

    $url = $baseUrl . '/' . ltrim($endpoint, '/');

    $ch = curl_init($url);
    $defaultOptions = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_HEADERFUNCTION => function ($curl, $header) use (&$headers) {
            $parts = explode(':', $header, 2);
            if (count($parts) === 2) {
                $headers[strtolower(trim($parts[0]))] = trim($parts[1]);
            }
            return strlen($header);
        }
    ];

    if ($method === 'POST') {
        if ($postFields !== null) {
            $defaultOptions[CURLOPT_POST] = true;
            $defaultOptions[CURLOPT_POSTFIELDS] = is_array($postFields)
                ? json_encode($postFields)
                : $postFields;
        } else {
            $defaultOptions[CURLOPT_CUSTOMREQUEST] = 'POST';
        }
    } elseif (in_array($method, ['DELETE', 'PUT', 'GET'])) {
        $defaultOptions[CURLOPT_CUSTOMREQUEST] = $method;
    }

    curl_setopt_array($ch, $defaultOptions);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);

    return [
        'success' => $response !== false && $httpCode < 400,
        'response' => $response,
        'http_code' => $httpCode,
        'error' => $error ?: null,
        'headers' => $headers
    ];
}
