<?php
declare(strict_types=1);

require_once __DIR__ . '/logger.php';
$config = require __DIR__ . '/../config/backend.config.php';

class OvaValidator
{
    private static $config;

    public function __construct(array $config)
    {
        self::$config = $config['upload'] ?? [];
        logDebug("Initialized OvaValidator");
    }

    public static function validate(string $ovaPath): void
    {
        $maxVirtualSizeBytes = self::$config['MAX_VIRTUAL_SIZE_BYTES'];
        $maxSingleVmdkSizeBytes = self::$config['MAX_SINGLE_VMDK_SIZE_BYTES'];
        $maxTotalVmdkSizeBytes = self::$config['MAX_TOTAL_VMDK_SIZE_BYTES'];
        $maxVmdkCount = self::$config['MAX_VMDK_COUNT'];
        $maxOvfSizeBytes = self::$config['MAX_OVF_SIZE_BYTES'];


        self::validateInputFile($ovaPath);
        $fileSize = filesize($ovaPath);

        $tmpDir = sys_get_temp_dir() . '/ova_check_' . uniqid();
        if (!mkdir($tmpDir, 0755, true)) {
            logError("Failed to create temp directory: " . $tmpDir);
            throw new RuntimeException("System error during validation", 500);
        }

        try {
            $output = self::listOvaContents($ovaPath);
            $ovfFile = self::findAndValidateOvfFile($output, $maxOvfSizeBytes);
            $ovfPath = self::extractOvfFile($ovaPath, $tmpDir, $ovfFile['name']);
            $xml = self::parseOvfFile($ovfPath);
            $disks = self::extractDiskInformation($xml);
            self::validateVirtualDisks($disks, $maxVirtualSizeBytes);
            $vmdkFiles = self::findAndValidateVmdkFiles($output, $maxSingleVmdkSizeBytes, $maxTotalVmdkSizeBytes, $maxVmdkCount);
            logDebug("OVA validation completed successfully");
        } finally {
            self::cleanupTempDir($tmpDir);
        }
    }

    private static function validateInputFile(string $ovaPath): void
    {
        if (!file_exists($ovaPath)) {
            logError("OVA file does not exist: " . $ovaPath);
            throw new InvalidArgumentException("Invalid OVA file", 400);
        }

        if (!is_readable($ovaPath)) {
            logError("OVA file is not readable: " . $ovaPath);
            throw new RuntimeException("Cannot read OVA file", 403);
        }
    }

    private static function listOvaContents(string $ovaPath): array
    {
        $cmd = "tar -tvf " . escapeshellarg($ovaPath) . " 2>&1";
        exec($cmd, $output, $ret);

        if ($ret !== 0) {
            $errorOutput = implode("\n", array_slice($output, 0, 5));
            logError("Failed to list OVA contents. Command: " . $cmd . " Output: " . $errorOutput);
            throw new RuntimeException("Invalid OVA file format", 400);
        }

        return $output;
    }

    private static function findAndValidateOvfFile(array $output, int $maxOvfSizeBytes): array
    {
        $pattern = '/^\S+\s+\S+\/\S+\s+(\d+)\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}\s+(.+\.ovf)$/i';
        $ovfFiles = [];

        foreach ($output as $line) {
            if (preg_match($pattern, $line, $matches)) {
                $size = (int)$matches[1];
                $filename = basename($matches[2]);

                if ($filename !== $matches[2]) {
                    logError("Suspicious OVF filename detected: " . $matches[2]);
                    throw new RuntimeException("Invalid OVF filename", 400);
                }

                if ($size > $maxOvfSizeBytes) {
                    logError("OVF file too large: " . $filename . " (" . self::formatBytes($size) . ")");
                    throw new RuntimeException("OVF file exceeds size limit", 400);
                }

                $ovfFiles[] = ['name' => $filename, 'size' => $size];
            }
        }

        if (count($ovfFiles) === 0) {
            logError("No OVF file found in OVA");
            throw new RuntimeException("No OVF file found in OVA package", 400);
        }

        if (count($ovfFiles) > 1) {
            logError("Multiple OVF files found in OVA");
            throw new RuntimeException("Multiple OVF files found - only one allowed", 400);
        }
        return $ovfFiles[0];
    }

    private static function extractOvfFile(string $ovaPath, string $tmpDir, string $ovfName): string
    {
        $cmd = "tar -xf " . escapeshellarg($ovaPath) . " -C " . escapeshellarg($tmpDir) . " " . escapeshellarg($ovfName) . " 2>&1";
        exec($cmd, $output, $ret);

        if ($ret !== 0) {
            $errorOutput = implode("\n", array_slice($output, 0, 5));
            logError("Failed to extract OVF file. Command: " . $cmd . " Output: " . $errorOutput);
            throw new RuntimeException("Failed to extract OVF from OVA", 400);
        }

        $ovfPath = $tmpDir . DIRECTORY_SEPARATOR . basename($ovfName);
        if (!file_exists($ovfPath)) {
            logError("Extracted OVF file not found at expected path: " . $ovfPath);
            throw new RuntimeException("System error during OVF extraction", 500);
        }

        return $ovfPath;
    }

    private static function parseOvfFile(string $ovfPath): SimpleXMLElement
    {
        $ovfContent = file_get_contents($ovfPath);
        if ($ovfContent === false) {
            logError("Failed to read OVF file: " . $ovfPath);
            throw new RuntimeException("Failed to read OVF contents", 500);
        }

        if (strpos($ovfContent, '<!ENTITY') !== false) {
            logError("OVF contains potential XXE vulnerability (ENTITY declaration)");
            throw new RuntimeException("Invalid OVF file - security violation", 400);
        }

        libxml_use_internal_errors(true);
        $xml = simplexml_load_string($ovfContent);
        if ($xml === false) {
            $errors = libxml_get_errors();
            $errorMessages = array_map(fn($e) => $e->message, $errors);
            libxml_clear_errors();

            logError("Invalid OVF XML: " . implode(", ", array_slice($errorMessages, 0, 3)));
            throw new RuntimeException("Invalid OVF XML format", 400);
        }

        try {
            $xml->registerXPathNamespace('ovf', 'http://schemas.dmtf.org/ovf/envelope/1');
        } catch (Exception $e) {
            logError("Failed to register OVF namespace: " . $e->getMessage());
            throw new RuntimeException("Invalid OVF namespace", 400);
        }

        return $xml;
    }

    private static function extractDiskInformation(SimpleXMLElement $xml): array
    {
        $disks = [];
        try {
            $diskNodes = $xml->xpath('//ovf:Disk') ?: [];
            foreach ($diskNodes as $disk) {
                $attrs = $disk->attributes('ovf', true) ?: $disk->attributes();

                if (!isset($attrs['capacity'])) {
                    logError("Disk element missing capacity attribute");
                    throw new RuntimeException("Invalid OVF - disk capacity missing", 400);
                }

                $capacity = (int)$attrs['capacity'];
                $units = strtolower((string)($attrs['capacityAllocationUnits'] ?? 'byte'));

                $size = match ($units) {
                    'byte', 'bytes' => $capacity,
                    'kb', 'kilobytes' => $capacity * 1024,
                    'mb', 'megabytes' => $capacity * 1024 ** 2,
                    'gb', 'gigabytes' => $capacity * 1024 ** 3,
                    'tb', 'terabytes' => $capacity * 1024 ** 4,
                    'byte * 2^20' => $capacity * 1024 ** 2,
                    default => throw new RuntimeException("Unsupported capacity unit: $units", 400),
                };

                if ($size <= 0) {
                    logError("Invalid disk size: " . $size);
                    throw new RuntimeException("Invalid disk size in OVF", 400);
                }

                $disks[] = $size;
            }
        } catch (RuntimeException $e) {
            logError("Error parsing disk information: " . $e->getMessage());
            throw $e;
        }

        return $disks;
    }

    private static function validateVirtualDisks(array $disks, int $maxVirtualSizeBytes): void
    {
        $declaredVirtualSize = array_sum($disks);
        if ($declaredVirtualSize > $maxVirtualSizeBytes) {
            logError("Declared virtual size exceeds limit: " . self::formatBytes($declaredVirtualSize));
            throw new RuntimeException("Virtual disk size exceeds maximum allowed", 400);
        }
    }

    private static function findAndValidateVmdkFiles(array $output, int $maxSingleVmdkSizeBytes, int $maxTotalVmdkSizeBytes, int $maxVmdkCount): array
    {
        $pattern = '/^\S+\s+\S+\/\S+\s+(\d+)\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}\s+(.+\.vmdk)$/i';
        $vmdkFiles = [];

        foreach ($output as $line) {
            if (preg_match($pattern, $line, $matches)) {
                $size = (int)$matches[1];
                $filename = basename($matches[2]);

                if ($filename !== $matches[2]) {
                    logError("Suspicious VMDK path detected: " . $matches[2]);
                    throw new RuntimeException("Invalid VMDK filename", 400);
                }

                $vmdkFiles[$filename] = $size;
            }
        }

        if (count($vmdkFiles) > $maxVmdkCount) {
            logError("Too many VMDK files: " . count($vmdkFiles));
            throw new RuntimeException("Too many disk files in OVA", 400);
        }

        $totalVmdkSize = array_sum($vmdkFiles);
        if ($totalVmdkSize > $maxTotalVmdkSizeBytes) {
            logError("Total VMDK size exceeds limit: " . self::formatBytes($totalVmdkSize));
            throw new RuntimeException("Total disk size exceeds maximum allowed", 400);
        }

        foreach ($vmdkFiles as $filename => $size) {
            if ($size > $maxSingleVmdkSizeBytes) {
                logError("VMDK file exceeds size limit: " . $filename . " (" . self::formatBytes($size) . ")");
                throw new RuntimeException("Disk file exceeds maximum allowed size", 400);
            }
        }
        return $vmdkFiles;
    }

    private static function cleanupTempDir(string $tmpDir): void
    {
        if (is_dir($tmpDir)) {
            try {
                system("rm -rf " . escapeshellarg($tmpDir));
            } catch (Exception $e) {
                logError("Failed to clean up temp directory: " . $tmpDir . " - " . $e->getMessage());
            }
        }
    }

    private static function formatBytes(int $bytes, int $precision = 2): string
    {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $bytes = max($bytes, 0);
        $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
        $pow = min($pow, count($units) - 1);
        $bytes /= (1 << (10 * $pow));
        return round($bytes, $precision) . ' .php' . $units[$pow];
    }
}