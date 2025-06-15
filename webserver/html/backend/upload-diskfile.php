<?php
declare(strict_types=1);

require_once __DIR__ . '/../includes/logger.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/curlHelper.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/check_ova.php';
$config = require __DIR__ . '/../config/backend.config.php';
$generalConfig = json_decode(file_get_contents(__DIR__ . '/../config/general.config.json'), true);

class OvaUploadHandler
{
    private PDO $pdo;
    private int $userId;
    private string $action;
    private array $inputData;
    private array $config;
    private array $generalConfig;

    public function __construct(array $config, array $generalConfig)
    {
        $this->config = $config;
        $this->generalConfig = $generalConfig;
        $this->pdo = getPDO();
        $this->initSession();
        $this->validateAccess();
        $this->userId = $_SESSION['user_id'];
        $this->action = $_GET['action'] ?? '';
        $this->inputData = $this->parseInputData();

        logDebug("Initialized OvaUploadHandler for User ID: {$this->userId}, Action: {$this->action}");
    }

    private function initSession(): void
    {
        try {
            init_secure_session();
        } catch (Exception $e) {
            logError("Session initialization failed: " . $e->getMessage());
            throw new RuntimeException('Session initialization error', 500);
        }
    }

    private function validateAccess(): void
    {
        if (!validate_session()) {
            logWarning("Unauthorized access attempt from IP: " . anonymizeIp($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
            throw new RuntimeException('Unauthorized - Please login', 401);
        }

        $csrfToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
        if (!validate_csrf_token($csrfToken)) {
            logWarning("Invalid CSRF token from user ID: " . ($_SESSION['user_id'] ?? 'unknown'));
            throw new RuntimeException('Invalid request token', 403);
        }

        if (!validate_admin_access($this->pdo)) {
            logWarning("Unauthorized admin access attempt by user ID: " . ($_SESSION['user_id'] ?? 'unknown'));
            throw new RuntimeException('Unauthorized - Admin access required', 403);
        }
    }

    private function parseInputData(): array
    {
        if ($_SERVER['REQUEST_METHOD'] === 'GET') {
            return [];
        }

        if ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
            $data = json_decode(file_get_contents('php://input'), true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                logError("Invalid JSON in OVA deletion - User ID: {$this->userId}");
                throw new RuntimeException('Invalid JSON data', 400);
            }
            return $data;
        }

        $jsonInput = json_decode(file_get_contents('php://input'), true);
        if ($jsonInput !== null) {
            return array_merge($_POST, $jsonInput);
        }

        return $_POST;
    }

    public function handleRequest(): void
    {
        try {
            $this->ensureUploadDirectory();

            switch ($_SERVER['REQUEST_METHOD']) {
                case 'POST':
                    $this->handlePostRequest();
                    break;
                case 'GET':
                case 'DELETE':
                    $this->handleGetOrDeleteRequest();
                    break;
                default:
                    throw new RuntimeException('Method not allowed', 405);
            }
        } catch (Exception $e) {
            $this->handleError($e);
        }
    }

    private function ensureUploadDirectory(): void
    {
        if (!file_exists($this->config['upload']['UPLOAD_TEMP_DIR']) && !mkdir($this->config['upload']['UPLOAD_TEMP_DIR'], 0755, true)) {
            logError("Failed to create upload directory: " . $this->config['upload']['UPLOAD_TEMP_DIR']);
            throw new RuntimeException('System configuration error', 500);
        }
    }

    private function handlePostRequest(): void
    {
        $uploadType = isset($this->inputData['uploadId']) ? 'chunked' : 'direct';
        logDebug("Upload initiated by user {$this->userId}, type: {$uploadType}");

        if ($uploadType === 'chunked') {
            $this->handleChunkedUpload();
        } else {
            $this->handleDirectUpload();
        }
    }

    private function handleChunkedUpload(): void
    {
        $phase = $this->inputData['phase'] ??
            (isset($_FILES['chunk']) ? 'chunk' :
                (isset($this->inputData['fileName']) ? 'init' : 'finalize'));

        switch ($phase) {
            case 'init':
                $this->handleChunkedInit();
                break;
            case 'chunk':
                $this->handleChunkUpload();
                break;
            case 'finalize':
                $this->handleChunkedFinalize();
                break;
            case 'cancel':
                $this->handleUploadCancellation();
            default:
                throw new RuntimeException('Invalid upload request', 400);
        }
    }

    private function handleChunkedInit(): void
    {
        $fileName = $this->sanitizeFilename($this->inputData['fileName']);
        $fileSize = (int)($this->inputData['fileSize'] ?? 0);
        $totalChunks = (int)($this->inputData['totalChunks'] ?? 0);

        logDebug("Chunked upload init for user {$this->userId}: {$fileName} ({$fileSize} bytes)");

        $this->validateFileSize($fileSize);
        $this->validateFileType($fileName);

        $displayName = pathinfo($fileName, PATHINFO_FILENAME);
        $this->checkDuplicateFileName($displayName);

        $uploadId = uniqid('upload_');
        $this->createUploadMetadata($uploadId, $fileName, $fileSize, $totalChunks);

        echo json_encode([
            'success' => true,
            'uploadId' => $uploadId,
            'chunkSize' => $this->generalConfig['upload']['CHUNK_SIZE']
        ]);
        exit;
    }

    private function handleChunkUpload(): void
    {
        $uploadId = $this->inputData['uploadId'];
        $chunkIndex = (int)$this->inputData['chunkIndex'];
        $chunkSize = $this->generalConfig['upload']['CHUNK_SIZE'];
        $tempFile = $this->config['upload']['UPLOAD_TEMP_DIR'] . $uploadId;

        $meta = $this->validateUploadSession($uploadId);

        $chunkTmpName = $_FILES['chunk']['tmp_name'];
        $chunkData = file_get_contents($chunkTmpName);
        if ($chunkData === false) {
            logError("Failed to read uploaded chunk {$chunkIndex} for upload {$uploadId}");
            throw new RuntimeException('File read failed', 500);
        }

        $combinedFile = $tempFile . '.combined';
        $out = fopen($combinedFile, 'c+b');
        if (!$out) {
            logError("Failed to open combined file for writing chunk {$chunkIndex} of upload {$uploadId}");
            throw new RuntimeException('File open failed', 500);
        }

        $offset = $chunkIndex * $chunkSize;
        if (fseek($out, $offset) !== 0) {
            fclose($out);
            logError("fseek failed for chunk {$chunkIndex} at offset {$offset} in upload {$uploadId}");
            throw new RuntimeException('File seek failed', 500);
        }

        if (fwrite($out, $chunkData) === false) {
            fclose($out);
            logError("Failed to write chunk {$chunkIndex} at offset {$offset} for upload {$uploadId}");
            throw new RuntimeException('File write failed', 500);
        }

        fclose($out);

        $this->updateUploadMetadata($uploadId, $meta);

        echo json_encode(['success' => true]);
        exit;
    }

    private function handleChunkedFinalize(): void
    {
        $uploadId = $this->inputData['uploadId'];
        $tempFile = $this->config['upload']['UPLOAD_TEMP_DIR'] . $uploadId;
        $proxmoxFilename = null;

        try {
            $meta = $this->validateUploadSession($uploadId);
            $this->verifyAllChunksReceived($uploadId, $meta);

            $combinedFile = $tempFile . '.combined';

            if (!file_exists($combinedFile)) {
                logError("Combined file missing for upload {$uploadId}");
                throw new RuntimeException('Combined file missing', 500);
            }

            $this->validateOvaFile($combinedFile);

            $uniqueName = uniqid('ova_') . '.' . pathinfo($meta['fileName'], PATHINFO_EXTENSION);
            $proxmoxFilename = $uniqueName;

            $this->uploadToProxmox(
                $combinedFile,
                pathinfo($meta['fileName'], PATHINFO_FILENAME),
                $uniqueName
            );

            $this->cleanupUploadFiles($uploadId, $combinedFile);

            logInfo("Chunked upload {$uploadId} completed successfully");

            echo json_encode([
                'success' => true,
                'message' => 'File uploaded successfully'
            ]);
        } catch (Exception $e) {
            if ($proxmoxFilename) {
                try {
                    $this->deleteFromProxmox($proxmoxFilename);
                } catch (Exception $deleteEx) {
                    logError("Failed to clean up Proxmox file during finalize: " . $deleteEx->getMessage());
                }
            }

            $this->cleanupPartialUpload($uploadId);

            throw $e;
        }
    }

    private function handleUploadCancellation(): void
    {
        $uploadId = $this->inputData['uploadId'] ?? null;

        if (empty($uploadId)) {
            throw new RuntimeException('Missing upload ID', 400);
        }
        $metaFile = $this->config['upload']['UPLOAD_TEMP_DIR'] . $uploadId . '.meta';
        if (!file_exists($metaFile)) {
            echo json_encode(['success' => true]);
            exit;
        }

        $meta = json_decode(file_get_contents($metaFile), true);
        if ($meta['userId'] !== $this->userId) {
            logWarning("User {$this->userId} attempted to cancel another user's upload");
            throw new RuntimeException('Unauthorized cancellation', 403);
        }

        $proxmoxFilename = $meta['proxmoxFilename'] ?? null;
        $this->cleanupPartialUpload($uploadId);

        if ($proxmoxFilename) {
            try {
                $this->deleteFromProxmox($proxmoxFilename);
            } catch (Exception $e) {
                logError("Failed to delete Proxmox file during cancellation: " . $e->getMessage());
            }
        }

        echo json_encode(['success' => true]);
        exit;
    }

    private function cleanupPartialUpload(string $uploadId): void
    {
        $files = [
            $this->config['upload']['UPLOAD_TEMP_DIR'] . $uploadId . '.combined',
            $this->config['upload']['UPLOAD_TEMP_DIR'] . $uploadId . '.meta',
            ...glob($this->config['upload']['UPLOAD_TEMP_DIR'] . $uploadId . '.part*')
        ];

        foreach ($files as $file) {
            if (file_exists($file)) {
                try {
                    unlink($file);
                } catch (Exception $e) {
                    logError("Failed to delete {$file}: " . $e->getMessage());
                }
            }
        }
    }

    private function handleDirectUpload(): void
    {
        if (!isset($_FILES['ova_file']) || $_FILES['ova_file']['error'] !== UPLOAD_ERR_OK) {
            $errorCode = $_FILES['ova_file']['error'] ?? 'unknown';

            if ($errorCode === UPLOAD_ERR_PARTIAL) {
                logWarning("Upload cancelled/timed out for user {$this->userId}");
                throw new RuntimeException('Upload was cancelled or timed out', 400);
            }

            logError("File upload error {$errorCode} for user {$this->userId}");
            throw new RuntimeException('File upload failed', 400);
        }

        $file = $_FILES['ova_file'];
        $tempPath = '';
        $uniqueName = '';

        try {
            $this->validateFileType($file['name']);
            $this->validateFileSize($file['size']);

            $originalName = pathinfo($file['name'], PATHINFO_FILENAME);
            $uniqueName = uniqid('ova_') . '.' . strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
            $tempPath = sys_get_temp_dir() . '/' . $uniqueName;

            ignore_user_abort(false);

            if (!move_uploaded_file($file['tmp_name'], $tempPath)) {
                throw new RuntimeException('File processing error', 500);
            }

            if (connection_aborted()) {
                logWarning("Client disconnected during direct upload processing");
                @unlink($tempPath);
                throw new RuntimeException('Upload cancelled', 400);
            }

            $this->validateOvaFile($tempPath);
            $this->uploadToProxmox($tempPath, $originalName, $uniqueName);

            if (connection_aborted()) {
                logWarning("Client disconnected during direct upload processing");
                @unlink($tempPath);
                throw new RuntimeException('Upload cancelled', 400);
            }

            logInfo("OVA upload completed successfully for user {$this->userId}");
            echo json_encode([
                'success' => true,
                'message' => 'File uploaded successfully'
            ]);
        } catch (Exception $e) {
            if (!empty($uniqueName) && $e->getCode() !== 400) {
                try {
                    $this->deleteFromProxmox($uniqueName);
                } catch (Exception $deleteEx) {
                    logError("Failed to clean up Proxmox file {$uniqueName}: " . $deleteEx->getMessage());
                }
            }

            if ($tempPath && file_exists($tempPath)) {
                @unlink($tempPath);
            }

            throw $e;
        } finally {
            if ($tempPath && file_exists($tempPath)) {
                @unlink($tempPath);
            }
        }
    }

    private function handleGetOrDeleteRequest(): void
    {
        switch ($this->action) {
            case 'list':
                $this->handleListAction();
                break;
            case 'delete':
                $this->handleDeleteAction();
                break;
            default:
                throw new RuntimeException('Invalid request', 400);
        }
    }

    private function handleListAction(): void
    {
        try {
            $stmt = $this->pdo->prepare("
                SELECT 
                    id,
                    display_name,
                    upload_date
                FROM disk_files
                WHERE user_id = :user_id
                ORDER BY upload_date DESC
            ");
            $stmt->execute(['user_id' => $this->userId]);
            $ovas = $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            logError("Database error listing files for user {$this->userId}: " . $e->getMessage());
            throw new RuntimeException('Could not retrieve file list', 500);
        }
        echo json_encode([
            'success' => true,
            'ovas' => $ovas
        ]);
    }

    private function handleDeleteAction(): void
    {
        $ovaId = $this->inputData['ova_id'] ?? null;

        if (empty($ovaId)) {
            throw new RuntimeException('Missing file ID', 400);
        }

        $ova = $this->getOvaForDeletion($ovaId);
        $this->deleteFromProxmox($ova['proxmox_filename']);
        $this->deleteFromDatabase($ovaId);

        logDebug("Successfully deleted OVA {$ovaId} for user {$this->userId}");
        echo json_encode([
            'success' => true,
            'message' => 'File deleted successfully'
        ]);
    }

    private function validateFileSize(int $fileSize): void
    {
        if ($fileSize > $this->generalConfig['upload']['MAX_FILE_SIZE']) {
            throw new RuntimeException('File too large', 400);
        }
    }

    private function validateFileType(string $fileName): void
    {
        $fileExt = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
        if (!in_array("." . $fileExt, $this->generalConfig['upload']['VALID_FILE_TYPES'])) {
            logError("Invalid file type attempt by user {$this->userId}: {$fileExt}");
            throw new RuntimeException('Invalid file type', 400);
        }
    }

    private function checkDuplicateFileName(string $displayName): void
    {
        try {
            $stmt = $this->pdo->prepare("
                SELECT COUNT(*) as count 
                FROM disk_files 
                WHERE user_id = :user_id AND display_name = :display_name
            ");
            $stmt->execute([
                'user_id' => $this->userId,
                'display_name' => $displayName
            ]);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            logError("Database error checking duplicate file name: " . $e->getMessage());
            throw new RuntimeException('Could not verify file name', 500);
        }

        if ($result['count'] > 0) {
            logError("Duplicate file name attempt by user {$this->userId}: {$displayName}");
            throw new RuntimeException('File name already exists', 400);
        }
    }

    private function createUploadMetadata(string $uploadId, string $fileName, int $fileSize, int $totalChunks): void
    {
        $metadata = [
            'fileName' => $fileName,
            'fileSize' => $fileSize,
            'totalChunks' => $totalChunks,
            'receivedChunks' => 0,
            'userId' => $this->userId,
            'uploadDate' => time()
        ];

        if (file_put_contents($this->config['upload']['UPLOAD_TEMP_DIR'] . $uploadId . '.meta', json_encode($metadata)) === false) {
            logError("Failed to create upload metadata file for upload {$uploadId}");
            throw new RuntimeException('Could not initialize upload', 500);
        }
    }

    private function validateUploadSession(string $uploadId): array
    {
        $metaFile = $this->config['upload']['UPLOAD_TEMP_DIR'] . $uploadId . '.meta';
        if (!file_exists($metaFile)) {
            throw new RuntimeException('Upload session expired', 404);
        }

        $meta = json_decode(file_get_contents($metaFile), true);
        if ($meta['userId'] !== $this->userId) {
            logError("User ID mismatch in chunk upload: {$this->userId} vs {$meta['userId']}");
            throw new RuntimeException('Upload session mismatch', 403);
        }

        return $meta;
    }

    private function updateUploadMetadata(string $uploadId, array $meta): void
    {
        $meta['receivedChunks']++;
        if (file_put_contents($this->config['upload']['UPLOAD_TEMP_DIR'] . $uploadId . '.meta', json_encode($meta)) === false) {
            logError("Failed to update metadata for upload {$uploadId}");
            throw new RuntimeException('Could not update upload status', 500);
        }
    }

    private function verifyAllChunksReceived(string $uploadId, array $meta): void
    {
        if ($meta['receivedChunks'] !== $meta['totalChunks']) {
            logError("Missing chunks in upload {$uploadId}: received {$meta['receivedChunks']} of {$meta['totalChunks']}");
            throw new RuntimeException('Upload incomplete', 400);
        }
    }

    private function validateOvaFile(string $filePath): void
    {
        try {
            $validator = new OvaValidator($this->config);
            $validator->validate($filePath);
        } catch (Exception $e) {
            @unlink($filePath);
            logError("OVA validation failed: " . $e->getMessage());
            throw $e;
        }
    }

    private function cleanupUploadFiles(string $uploadId, string $finalPath): void
    {
        unlink($finalPath);
        unlink($this->config['upload']['UPLOAD_TEMP_DIR'] . $uploadId . '.meta');
    }

    private function uploadToProxmox(string $filePath, string $displayName, string $proxmoxFilename): void
    {

        $this->checkDuplicateFileName($displayName);

        $endpoint = "/api2/json/nodes/" . $this->config['upload']['NODE'] . "/storage/local/upload";
        $postParams = [
            'content' => 'import',
            'filename' => new CURLFile(
                $filePath,
                'application/octet-stream',
                $proxmoxFilename
            )
        ];

        $authHeaders = getAuthHeaders("multipart/form-data");
        $result = makeCurlRequest($endpoint, 'POST', $authHeaders, $postParams);

        if (!$result) {
            logError("Proxmox API connection failed for user {$this->userId}");
            throw new RuntimeException('Server connection failed', 500);
        }

        $responseData = json_decode($result['response'], true);
        $httpCode = $result['http_code'];

        if ($httpCode !== 200) {
            $error = $responseData['errors'] ?? 'Unknown error';
            logError("Proxmox upload failed for user {$this->userId}: HTTP {$httpCode} - " . json_encode($error));
            throw new RuntimeException('File processing failed', 500);
        }

        $this->storeFileMetadata($displayName, $proxmoxFilename);
    }

    private function storeFileMetadata(string $displayName, string $proxmoxFilename): void
    {
        $this->pdo->beginTransaction();
        try {
            $stmt = $this->pdo->prepare("
                INSERT INTO disk_files (
                    user_id, 
                    display_name, 
                    proxmox_filename
                ) VALUES (
                    :user_id, 
                    :display_name, 
                    :proxmox_filename
                )
            ");
            $stmt->execute([
                'user_id' => $this->userId,
                'display_name' => $displayName,
                'proxmox_filename' => $proxmoxFilename
            ]);
            $this->pdo->commit();
        } catch (PDOException $e) {
            $this->pdo->rollBack();
            logError("Database error saving file metadata: " . $e->getMessage());
            throw new RuntimeException('Could not save file information', 500);
        }
    }

    private function getOvaForDeletion(string $ovaId): array
    {
        try {
            $stmt = $this->pdo->prepare("
                SELECT proxmox_filename 
                FROM disk_files 
                WHERE id = :ova_id AND user_id = :user_id
            ");
            $stmt->execute(['ova_id' => $ovaId, 'user_id' => $this->userId]);
            $ova = $stmt->fetch();
        } catch (PDOException $e) {
            logError("Database error fetching OVA {$ovaId} for deletion: " . $e->getMessage());
            throw new RuntimeException('Could not retrieve file information', 500);
        }

        if (!$ova) {
            logError("Delete attempt for non-existent OVA {$ovaId} by user {$this->userId}");
            throw new RuntimeException('File not found', 404);
        }

        return $ova;
    }

    private function deleteFromProxmox(string $proxmoxFilename): void
    {
        $endpoint = "/api2/json/nodes/" . $this->config['upload']['NODE'] . "/storage/local/content/import/" . urlencode($proxmoxFilename);
        $authHeaders = getAuthHeaders();
        $result = makeCurlRequest($endpoint, 'DELETE', $authHeaders);

        if (!$result || $result['http_code'] !== 200) {
            logError("Proxmox delete failed for file {$proxmoxFilename} by user {$this->userId}");
            throw new RuntimeException('File deletion failed', 500);
        }
    }

    private function deleteFromDatabase(string $ovaId): void
    {
        try {
            $stmt = $this->pdo->prepare("
                DELETE FROM disk_files 
                WHERE id = :ova_id AND user_id = :user_id
            ");
            $stmt->execute(['ova_id' => $ovaId, 'user_id' => $this->userId]);
        } catch (PDOException $e) {
            logError("Database error deleting OVA {$ovaId}: " . $e->getMessage());
            throw new RuntimeException('Could not complete file deletion', 500);
        }
    }

    private function sanitizeFilename(string $filename): string
    {
        return preg_replace('/[^a-zA-Z0-9\-_\.]/', '', $filename);
    }

    private function handleError(Exception $e): void
    {
        $code = $e->getCode() >= 400 && $e->getCode() < 600 ? $e->getCode() : 500;
        http_response_code($code);

        logError("OVA route error [{$code}]: " . $e->getMessage() . " | User: {$this->userId} | Action: {$this->action}");

        echo json_encode([
            'success' => false,
            'message' => $e->getMessage(),
            'error_code' => $code,
            'redirect' => $code === 401 ? '/login' : null
        ]);
        exit;
    }
}

try {
    $handler = new OvaUploadHandler($config, $generalConfig);
    $handler->handleRequest();
} catch (Exception $e) {
    $errorCode = $e->getCode() ?: 500;
    http_response_code($errorCode);
    logError("Error in upload-diskfile endpoint: " . $e->getMessage() . " (Code: $errorCode)");
    $response = [
        'success' => false,
        'message' => $e->getMessage()
    ];

    if ($errorCode === 401) {
        $response['redirect'] = '/login';
    }

    echo json_encode($response);
}