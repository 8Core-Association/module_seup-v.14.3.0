<?php

/**
 * Nextcloud API integration for SEUP module
 * (c) 2025 8Core Association
 */

class NextcloudAPI
{
    private $baseUrl;
    private $username;
    private $password;
    private $db;
    private $conf;
    private $isECMNextcloudMounted;

    public function __construct($db, $conf)
    {
        $this->db = $db;
        $this->conf = $conf;
        
        // Get Nextcloud configuration from Dolibarr settings
        $this->baseUrl = getDolGlobalString('NEXTCLOUD_URL', 'https://your-nextcloud.com');
        $this->username = getDolGlobalString('NEXTCLOUD_USERNAME', '');
        $this->password = getDolGlobalString('NEXTCLOUD_PASSWORD', '');
        
        // Check if ECM is mounted as Nextcloud external disk
        $this->isECMNextcloudMounted = $this->checkECMNextcloudMount();
    }

    /**
     * Check if Dolibarr ECM is configured as Nextcloud external disk
     */
    private function checkECMNextcloudMount()
    {
        // Check if ECM data directory is mounted as Nextcloud external storage
        $ecmPath = DOL_DATA_ROOT . '/ecm';
        $nextcloudIndicator = $ecmPath . '/.nextcloud_mount';
        
        // Alternative: Check if ECM path contains Nextcloud data directory pattern
        $isNextcloudPath = (strpos($ecmPath, 'nextcloud') !== false || 
                           strpos($ecmPath, '/data/') !== false ||
                           getDolGlobalString('ECM_IS_NEXTCLOUD_MOUNT', '0') === '1');
        
        return file_exists($nextcloudIndicator) || $isNextcloudPath;
    }

    /**
     * Check if ECM is mounted as Nextcloud external disk
     */
    public function isECMNextcloudMounted()
    {
        return $this->isECMNextcloudMounted;
    }

    /**
     * Get files from Nextcloud folder
     */
    public function getFilesFromFolder($folderPath)
    {
        if (empty($this->username) || empty($this->password)) {
            dol_syslog("Nextcloud credentials not configured", LOG_WARNING);
            return [];
        }

        $url = $this->baseUrl . '/remote.php/dav/files/' . $this->username . '/' . ltrim($folderPath, '/');
        
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST => 'PROPFIND',
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/xml',
                'Depth: 1'
            ],
            CURLOPT_USERPWD => $this->username . ':' . $this->password,
            CURLOPT_POSTFIELDS => '<?xml version="1.0"?>
                <d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">
                    <d:prop>
                        <d:displayname/>
                        <d:getcontentlength/>
                        <d:getcontenttype/>
                        <d:getlastmodified/>
                        <d:getetag/>
                        <oc:size/>
                        <oc:id/>
                        <oc:tags/>
                        <oc:comments-count/>
                        <oc:share-types/>
                    </d:prop>
                </d:propfind>',
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_TIMEOUT => 30
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 207) {
            dol_syslog("Nextcloud API error: HTTP $httpCode", LOG_ERR);
            return [];
        }

        return $this->parseWebDAVResponse($response, $folderPath);
    }

    /**
     * Parse WebDAV XML response
     */
    private function parseWebDAVResponse($xmlResponse, $folderPath)
    {
        $files = [];
        
        try {
            $xml = simplexml_load_string($xmlResponse);
            if (!$xml) {
                return [];
            }

            $xml->registerXPathNamespace('d', 'DAV:');
            $xml->registerXPathNamespace('oc', 'http://owncloud.org/ns');

            $responses = $xml->xpath('//d:response');
            
            foreach ($responses as $response) {
                $href = (string)$response->xpath('d:href')[0];
                $props = $response->xpath('d:propstat/d:prop')[0];
                
                // Skip the folder itself
                if (rtrim($href, '/') === rtrim('/remote.php/dav/files/' . $this->username . '/' . $folderPath, '/')) {
                    continue;
                }

                $filename = (string)$props->xpath('d:displayname')[0];
                if (empty($filename)) continue;

                $size = (string)$props->xpath('d:getcontentlength')[0];
                $contentType = (string)$props->xpath('d:getcontenttype')[0];
                $lastModified = (string)$props->xpath('d:getlastmodified')[0];
                $etag = (string)$props->xpath('d:getetag')[0];
                
                // Nextcloud specific properties
                $ncSize = $props->xpath('oc:size')[0];
                $ncId = $props->xpath('oc:id')[0];
                $ncTags = $props->xpath('oc:tags')[0];
                $ncComments = $props->xpath('oc:comments-count')[0];
                $ncShares = $props->xpath('oc:share-types')[0];

                $files[] = [
                    'filename' => $filename,
                    'size' => $size ?: (string)$ncSize,
                    'content_type' => $contentType,
                    'last_modified' => $lastModified,
                    'etag' => trim($etag, '"'),
                    'nextcloud_id' => (string)$ncId,
                    'tags' => (string)$ncTags,
                    'comments_count' => (int)$ncComments,
                    'is_shared' => !empty($ncShares),
                    'download_url' => $this->generateDownloadUrl($folderPath, $filename),
                    'edit_url' => $this->generateEditUrl($folderPath, $filename),
                    'source' => 'nextcloud'
                ];
            }
        } catch (Exception $e) {
            dol_syslog("Error parsing Nextcloud response: " . $e->getMessage(), LOG_ERR);
        }

        return $files;
    }

    /**
     * Generate download URL for Nextcloud file
     */
    private function generateDownloadUrl($folderPath, $filename)
    {
        $encodedPath = rawurlencode($folderPath . '/' . $filename);
        return $this->baseUrl . '/remote.php/dav/files/' . $this->username . '/' . $encodedPath;
    }

    /**
     * Generate edit URL for Nextcloud file (OnlyOffice/Collabora)
     */
    private function generateEditUrl($folderPath, $filename)
    {
        $fileId = $this->getFileId($folderPath, $filename);
        if ($fileId) {
            return $this->baseUrl . '/apps/files/?fileid=' . $fileId;
        }
        return null;
    }

    /**
     * Get Nextcloud file ID
     */
    private function getFileId($folderPath, $filename)
    {
        // This would require additional API call or caching
        // For now, return null - can be implemented later
        return null;
    }

    /**
     * Upload file to Nextcloud
     * Only used if ECM is NOT mounted as Nextcloud external disk
     */
    public function uploadFile($localFilePath, $nextcloudPath, $filename)
    {
        // Skip upload if ECM is already Nextcloud mounted
        if ($this->isECMNextcloudMounted) {
            dol_syslog("Skipping Nextcloud upload - ECM is already Nextcloud mounted", LOG_INFO);
            return true; // Return success since file is already there
        }
        
        $url = $this->baseUrl . '/remote.php/dav/files/' . $this->username . '/' . ltrim($nextcloudPath, '/') . '/' . $filename;
        
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST => 'PUT',
            CURLOPT_USERPWD => $this->username . ':' . $this->password,
            CURLOPT_POSTFIELDS => file_get_contents($localFilePath),
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/octet-stream'
            ],
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_TIMEOUT => 60
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        return ($httpCode >= 200 && $httpCode < 300);
    }

    /**
     * Create folder in Nextcloud
     * Only used if ECM is NOT mounted as Nextcloud external disk
     */
    public function createFolder($folderPath)
    {
        // Skip folder creation if ECM is already Nextcloud mounted
        if ($this->isECMNextcloudMounted) {
            dol_syslog("Skipping Nextcloud folder creation - ECM is already Nextcloud mounted", LOG_INFO);
            return true; // Return success since folder will be created by ECM
        }
        
        $url = $this->baseUrl . '/remote.php/dav/files/' . $this->username . '/' . ltrim($folderPath, '/');
        
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST => 'MKCOL',
            CURLOPT_USERPWD => $this->username . ':' . $this->password,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_TIMEOUT => 30
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        return ($httpCode >= 200 && $httpCode < 300);
    }

    /**
     * Set tags on Nextcloud file
     */
    public function setFileTags($filePath, $tags)
    {
        // Implementation for setting tags via Nextcloud API
        // This requires Nextcloud Tags API
        $url = $this->baseUrl . '/ocs/v2.php/apps/files/api/v1/files/' . rawurlencode($filePath) . '/tags';
        
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_USERPWD => $this->username . ':' . $this->password,
            CURLOPT_POSTFIELDS => json_encode(['tags' => $tags]),
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'OCS-APIRequest: true'
            ],
            CURLOPT_SSL_VERIFYPEER => false
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        return ($httpCode >= 200 && $httpCode < 300);
    }

    /**
     * Get file sharing information
     */
    public function getFileShares($filePath)
    {
        $url = $this->baseUrl . '/ocs/v2.php/apps/files_sharing/api/v1/shares?path=' . rawurlencode($filePath);
        
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_USERPWD => $this->username . ':' . $this->password,
            CURLOPT_HTTPHEADER => [
                'OCS-APIRequest: true',
                'Accept: application/json'
            ],
            CURLOPT_SSL_VERIFYPEER => false
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode === 200) {
            $data = json_decode($response, true);
            return $data['ocs']['data'] ?? [];
        }

        return [];
    }
}