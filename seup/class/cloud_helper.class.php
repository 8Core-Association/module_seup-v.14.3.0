<?php

/**
 * Plaćena licenca
 * (c) 2025 8Core Association
 * Tomislav Galić <tomislav@8core.hr>
 * Marko Šimunović <marko@8core.hr>
 * Web: https://8core.hr
 * Kontakt: info@8core.hr | Tel: +385 099 851 0717
 * Sva prava pridržana. Ovaj softver je vlasnički i zaštićen je autorskim i srodnim pravima 
 * te ga je izričito zabranjeno umnožavati, distribuirati, mijenjati, objavljivati ili 
 * na drugi način eksploatirati bez pismenog odobrenja autora.
 */

/**
 * Cloud Helper Class for SEUP Module
 * Handles cloud integrations (Nextcloud, future cloud services)
 */
class Cloud_helper
{
    /**
     * Sync Nextcloud files to Dolibarr ECM database
     * Creates ECM records for files that exist in Nextcloud but not in ECM database
     */
    public static function syncNextcloudToECM($db, $conf, $user, $predmet_id)
    {
        try {
            // Check if Nextcloud is enabled and configured
            if (!getDolGlobalString('NEXTCLOUD_ENABLED', '0') || 
                empty(getDolGlobalString('NEXTCLOUD_URL')) ||
                empty(getDolGlobalString('NEXTCLOUD_USERNAME')) ||
                empty(getDolGlobalString('NEXTCLOUD_PASSWORD'))) {
                dol_syslog("Nextcloud not configured, skipping sync", LOG_INFO);
                return ['success' => true, 'message' => 'Nextcloud not configured', 'synced' => 0];
            }

            require_once __DIR__ . '/nextcloud_api.class.php';
            require_once __DIR__ . '/predmet_helper.class.php';
            require_once DOL_DOCUMENT_ROOT . '/ecm/class/ecmfiles.class.php';

            $nextcloudApi = new NextcloudAPI($db, $conf);
            $relative_path = Predmet_helper::getPredmetFolderPath($predmet_id, $db);
            
            // Get files from Nextcloud
            $nextcloudFiles = $nextcloudApi->getFilesFromFolder($relative_path);
            
            if (empty($nextcloudFiles)) {
                return ['success' => true, 'message' => 'No files in Nextcloud folder', 'synced' => 0];
            }

            $syncedCount = 0;
            $errors = [];

            foreach ($nextcloudFiles as $file) {
                // Check if file already exists in ECM database
                $sql = "SELECT rowid FROM " . MAIN_DB_PREFIX . "ecm_files 
                        WHERE filepath = '" . $db->escape(rtrim($relative_path, '/')) . "'
                        AND filename = '" . $db->escape($file['filename']) . "'
                        AND entity = " . $conf->entity;
                
                $resql = $db->query($sql);
                if ($resql && $db->num_rows($resql) == 0) {
                    // File doesn't exist in ECM - create record
                    $ecmfile = new EcmFiles($db);
                    $ecmfile->filepath = rtrim($relative_path, '/');
                    $ecmfile->filename = $file['filename'];
                    $ecmfile->label = $file['filename'];
                    $ecmfile->entity = $conf->entity;
                    $ecmfile->gen_or_uploaded = 'uploaded';
                    $ecmfile->description = 'Synced from Nextcloud';
                    $ecmfile->fk_user_c = $user->id;
                    $ecmfile->fk_user_m = $user->id;
                    
                    // Convert Nextcloud date format to timestamp
                    $lastModified = strtotime($file['last_modified']);
                    $ecmfile->date_c = $lastModified ?: dol_now();
                    $ecmfile->date_m = $lastModified ?: dol_now();
                    
                    $result = $ecmfile->create($user);
                    if ($result > 0) {
                        $syncedCount++;
                        dol_syslog("Synced file from Nextcloud: " . $file['filename'], LOG_INFO);
                    } else {
                        $errors[] = "Failed to sync: " . $file['filename'] . " - " . $ecmfile->error;
                        dol_syslog("Failed to sync file: " . $file['filename'] . " - " . $ecmfile->error, LOG_ERR);
                    }
                }
            }

            $message = "Synced {$syncedCount} files from Nextcloud";
            if (!empty($errors)) {
                $message .= ". Errors: " . implode(', ', $errors);
            }

            return [
                'success' => true,
                'message' => $message,
                'synced' => $syncedCount,
                'errors' => $errors
            ];

        } catch (Exception $e) {
            dol_syslog("Nextcloud sync error: " . $e->getMessage(), LOG_ERR);
            return [
                'success' => false,
                'error' => $e->getMessage(),
                'synced' => 0
            ];
        }
    }

    /**
     * Sync ECM files to Nextcloud (upload missing files)
     * Optimized for ECM-Nextcloud mount detection
     */
    public static function syncECMToNextcloud($db, $conf, $user, $predmet_id)
    {
        try {
            if (!self::isNextcloudConfigured()) {
                return ['success' => true, 'message' => 'Nextcloud not configured', 'synced' => 0];
            }

            require_once __DIR__ . '/nextcloud_api.class.php';
            require_once __DIR__ . '/predmet_helper.class.php';

            $nextcloudApi = new NextcloudAPI($db, $conf);
            
            // If ECM is mounted as Nextcloud external disk, skip upload
            if ($nextcloudApi->isECMNextcloudMounted()) {
                return [
                    'success' => true, 
                    'message' => 'ECM is mounted as Nextcloud external disk - no upload needed', 
                    'synced' => 0
                ];
            }
            
            $relative_path = Predmet_helper::getPredmetFolderPath($predmet_id, $db);
            
            // Get ECM files for this predmet
            $sql = "SELECT filename, filepath FROM " . MAIN_DB_PREFIX . "ecm_files 
                    WHERE filepath = '" . $db->escape(rtrim($relative_path, '/')) . "'
                    AND entity = " . $conf->entity;
            
            $resql = $db->query($sql);
            $ecmFiles = [];
            if ($resql) {
                while ($obj = $db->fetch_object($resql)) {
                    $ecmFiles[] = $obj;
                }
            }

            // Get Nextcloud files to compare
            $nextcloudFiles = $nextcloudApi->getFilesFromFolder($relative_path);
            $nextcloudFilenames = array_column($nextcloudFiles, 'filename');

            $syncedCount = 0;
            $errors = [];

            // Create Nextcloud folder if it doesn't exist
            $nextcloudApi->createFolder($relative_path);

            foreach ($ecmFiles as $ecmFile) {
                if (!in_array($ecmFile->filename, $nextcloudFilenames)) {
                    // File exists in ECM but not in Nextcloud - upload it
                    $localFilePath = DOL_DATA_ROOT . '/ecm/' . $relative_path . $ecmFile->filename;
                    
                    if (file_exists($localFilePath)) {
                        $success = $nextcloudApi->uploadFile(
                            $localFilePath,
                            $relative_path,
                            $ecmFile->filename
                        );
                        
                        if ($success) {
                            $syncedCount++;
                            dol_syslog("Synced file to Nextcloud: " . $ecmFile->filename, LOG_INFO);
                        } else {
                            $errors[] = "Failed to upload: " . $ecmFile->filename;
                        }
                    }
                }
            }

            return [
                'success' => true,
                'message' => "Synced {$syncedCount} files to Nextcloud",
                'synced' => $syncedCount,
                'errors' => $errors
            ];

        } catch (Exception $e) {
            dol_syslog("ECM to Nextcloud sync error: " . $e->getMessage(), LOG_ERR);
            return [
                'success' => false,
                'error' => $e->getMessage(),
                'synced' => 0
            ];
        }
    }

    /**
     * Bidirectional sync - sync both ways
     * Optimized for ECM-Nextcloud mount scenarios
     */
    public static function bidirectionalSync($db, $conf, $user, $predmet_id)
    {
        require_once __DIR__ . '/nextcloud_api.class.php';
        $nextcloudApi = new NextcloudAPI($db, $conf);
        
        if ($nextcloudApi->isECMNextcloudMounted()) {
            // If ECM is Nextcloud mounted, only sync metadata from Nextcloud to ECM
            $results = [
                'nextcloud_to_ecm' => self::syncNextcloudToECM($db, $conf, $user, $predmet_id),
                'ecm_to_nextcloud' => ['success' => true, 'message' => 'ECM mounted - no upload needed', 'synced' => 0]
            ];
        } else {
            // Traditional bidirectional sync
            $results = [
                'nextcloud_to_ecm' => self::syncNextcloudToECM($db, $conf, $user, $predmet_id),
                'ecm_to_nextcloud' => self::syncECMToNextcloud($db, $conf, $user, $predmet_id)
            ];
        }

        $totalSynced = $results['nextcloud_to_ecm']['synced'] + $results['ecm_to_nextcloud']['synced'];
        
        return [
            'success' => $results['nextcloud_to_ecm']['success'] && $results['ecm_to_nextcloud']['success'],
            'message' => "Total synced: {$totalSynced} files",
            'details' => $results,
            'total_synced' => $totalSynced
        ];
    }

    /**
     * Bulk sync all predmeti
     */
    public static function bulkSyncAllPredmeti($db, $conf, $user, $limit = 50)
    {
        try {
            if (!self::isNextcloudConfigured()) {
                return ['success' => false, 'error' => 'Nextcloud not configured'];
            }

            // Get all active predmeti (not archived)
            $sql = "SELECT ID_predmeta FROM " . MAIN_DB_PREFIX . "a_predmet 
                    WHERE ID_predmeta NOT IN (
                        SELECT ID_predmeta FROM " . MAIN_DB_PREFIX . "a_arhiva 
                        WHERE status_arhive = 'active'
                    )
                    LIMIT " . (int)$limit;

            $resql = $db->query($sql);
            $predmeti = [];
            if ($resql) {
                while ($obj = $db->fetch_object($resql)) {
                    $predmeti[] = $obj->ID_predmeta;
                }
            }

            $totalSynced = 0;
            $processedCount = 0;
            $errors = [];

            foreach ($predmeti as $predmet_id) {
                $result = self::syncNextcloudToECM($db, $conf, $user, $predmet_id);
                $processedCount++;
                
                if ($result['success']) {
                    $totalSynced += $result['synced'];
                } else {
                    $errors[] = "Predmet {$predmet_id}: " . $result['error'];
                }

                // Add small delay to prevent overwhelming the server
                usleep(100000); // 0.1 second
            }

            return [
                'success' => true,
                'message' => "Processed {$processedCount} predmeti, synced {$totalSynced} files",
                'processed' => $processedCount,
                'synced' => $totalSynced,
                'errors' => $errors
            ];

        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * Validate Nextcloud connection
     */
    public static function validateNextcloudConnection($db, $conf)
    {
        try {
            if (!self::isNextcloudConfigured()) {
                return ['success' => false, 'error' => 'Nextcloud not configured'];
            }

            require_once __DIR__ . '/nextcloud_api.class.php';
            $nextcloudApi = new NextcloudAPI($db, $conf);
            
            // Try to list root SEUP folder
            $files = $nextcloudApi->getFilesFromFolder('SEUP/');
            
            return [
                'success' => true,
                'message' => 'Nextcloud connection successful',
                'files_found' => count($files)
            ];

        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * Get Nextcloud file metadata
     */
    public static function getNextcloudFileMetadata($db, $conf, $filepath, $filename)
    {
        try {
            if (!self::isNextcloudConfigured()) {
                return null;
            }

            require_once __DIR__ . '/nextcloud_api.class.php';
            $nextcloudApi = new NextcloudAPI($db, $conf);
            
            $files = $nextcloudApi->getFilesFromFolder($filepath);
            
            foreach ($files as $file) {
                if ($file['filename'] === $filename) {
                    return $file;
                }
            }

            return null;

        } catch (Exception $e) {
            dol_syslog("Error getting Nextcloud metadata: " . $e->getMessage(), LOG_ERR);
            return null;
        }
    }

    /**
     * Cleanup orphaned files (files in ECM database but not in filesystem/Nextcloud)
     */
    public static function cleanupOrphanedFiles($db, $conf, $user, $dryRun = true)
    {
        try {
            $orphanedFiles = [];
            $cleanedCount = 0;

            // Get all ECM files for SEUP
            $sql = "SELECT rowid, filepath, filename FROM " . MAIN_DB_PREFIX . "ecm_files 
                    WHERE filepath LIKE 'SEUP%'
                    AND entity = " . $conf->entity;

            $resql = $db->query($sql);
            if ($resql) {
                while ($obj = $db->fetch_object($resql)) {
                    $fullPath = DOL_DATA_ROOT . '/ecm/' . $obj->filepath . '/' . $obj->filename;
                    
                    // Check if file exists in filesystem
                    if (!file_exists($fullPath)) {
                        $orphanedFiles[] = [
                            'rowid' => $obj->rowid,
                            'filepath' => $obj->filepath,
                            'filename' => $obj->filename,
                            'full_path' => $fullPath
                        ];

                        // If not dry run, delete the ECM record
                        if (!$dryRun) {
                            $deleteSql = "DELETE FROM " . MAIN_DB_PREFIX . "ecm_files 
                                         WHERE rowid = " . (int)$obj->rowid;
                            if ($db->query($deleteSql)) {
                                $cleanedCount++;
                                dol_syslog("Cleaned orphaned ECM record: " . $obj->filename, LOG_INFO);
                            }
                        }
                    }
                }
            }

            return [
                'success' => true,
                'orphaned_files' => $orphanedFiles,
                'orphaned_count' => count($orphanedFiles),
                'cleaned_count' => $cleanedCount,
                'dry_run' => $dryRun
            ];

        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * Get sync status for a predmet
     */
    public static function getSyncStatus($db, $conf, $predmet_id)
    {
        try {
            if (!self::isNextcloudConfigured()) {
                return [
                    'nextcloud_enabled' => false,
                    'ecm_files' => 0,
                    'nextcloud_files' => 0,
                    'sync_needed' => false
                ];
            }

            require_once __DIR__ . '/nextcloud_api.class.php';
            require_once __DIR__ . '/predmet_helper.class.php';

            $nextcloudApi = new NextcloudAPI($db, $conf);
            $relative_path = Predmet_helper::getPredmetFolderPath($predmet_id, $db);

            // Count ECM files
            $sql = "SELECT COUNT(*) as count FROM " . MAIN_DB_PREFIX . "ecm_files 
                    WHERE filepath = '" . $db->escape(rtrim($relative_path, '/')) . "'
                    AND entity = " . $conf->entity;
            $resql = $db->query($sql);
            $ecmCount = 0;
            if ($resql && $obj = $db->fetch_object($resql)) {
                $ecmCount = (int)$obj->count;
            }

            // Count Nextcloud files
            $nextcloudFiles = $nextcloudApi->getFilesFromFolder($relative_path);
            $nextcloudCount = count($nextcloudFiles);

            return [
                'nextcloud_enabled' => true,
                'ecm_files' => $ecmCount,
                'nextcloud_files' => $nextcloudCount,
                'sync_needed' => ($ecmCount !== $nextcloudCount),
                'last_check' => date('Y-m-d H:i:s')
            ];

        } catch (Exception $e) {
            dol_syslog("Error getting sync status: " . $e->getMessage(), LOG_ERR);
            return [
                'nextcloud_enabled' => true,
                'error' => $e->getMessage(),
                'sync_needed' => true
            ];
        }
    }

    /**
     * Auto-sync files when accessing predmet (called automatically)
     */
    public static function autoSyncPredmet($db, $conf, $user, $predmet_id)
    {
        // Only auto-sync if Nextcloud is properly configured
        if (!self::isNextcloudConfigured()) {
            return ['success' => true, 'message' => 'Auto-sync skipped - Nextcloud not configured'];
        }

        // Check if we need to sync (simple time-based check)
        $lastSyncKey = "SEUP_LAST_SYNC_" . $predmet_id;
        $lastSync = getDolGlobalString($lastSyncKey, '0');
        $now = time();
        
        // Auto-sync every 5 minutes maximum
        if (($now - (int)$lastSync) > 300) {
            $result = self::syncNextcloudToECM($db, $conf, $user, $predmet_id);
            
            // Update last sync time
            dolibarr_set_const($db, $lastSyncKey, $now, 'chaine', 0, '', $conf->entity);
            
            return $result;
        }

        return ['success' => true, 'message' => 'Auto-sync skipped - too recent'];
    }

    /**
     * Check if Nextcloud is properly configured
     */
    public static function isNextcloudConfigured()
    {
        return getDolGlobalString('NEXTCLOUD_ENABLED', '0') === '1' &&
               !empty(getDolGlobalString('NEXTCLOUD_URL')) &&
               !empty(getDolGlobalString('NEXTCLOUD_USERNAME')) &&
               !empty(getDolGlobalString('NEXTCLOUD_PASSWORD'));
    }

    /**
     * Get Nextcloud configuration status
     */
    public static function getNextcloudStatus()
    {
        $url = getDolGlobalString('NEXTCLOUD_URL', '');
        $username = getDolGlobalString('NEXTCLOUD_USERNAME', '');
        $password = getDolGlobalString('NEXTCLOUD_PASSWORD', '');
        $enabled = getDolGlobalString('NEXTCLOUD_ENABLED', '0');

        $status = 'not_configured';
        if (!empty($url) && !empty($username) && !empty($password)) {
            $status = $enabled === '1' ? 'active' : 'configured_inactive';
        } elseif (!empty($url) || !empty($username)) {
            $status = 'partially_configured';
        }

        return [
            'status' => $status,
            'enabled' => $enabled === '1',
            'url' => $url,
            'username' => $username,
            'has_password' => !empty($password)
        ];
    }

    /**
     * Force refresh ECM cache for a predmet folder
     */
    public static function refreshECMCache($db, $conf, $predmet_id)
    {
        try {
            require_once __DIR__ . '/predmet_helper.class.php';
            $relative_path = Predmet_helper::getPredmetFolderPath($predmet_id, $db);
            $full_path = DOL_DATA_ROOT . '/ecm/' . $relative_path;

            // Clear any ECM cache if it exists
            if (function_exists('dol_delete_dir_recursive')) {
                $cache_path = $full_path . '.cache';
                if (is_dir($cache_path)) {
                    dol_delete_dir_recursive($cache_path);
                }
            }

            return ['success' => true, 'message' => 'ECM cache refreshed'];

        } catch (Exception $e) {
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    /**
     * Get detailed sync report for admin
     */
    public static function getSyncReport($db, $conf)
    {
        try {
            $report = [
                'nextcloud_status' => self::getNextcloudStatus(),
                'total_predmeti' => 0,
                'synced_predmeti' => 0,
                'sync_issues' => [],
                'last_generated' => date('Y-m-d H:i:s')
            ];

            if (!self::isNextcloudConfigured()) {
                return $report;
            }

            // Count total predmeti
            $sql = "SELECT COUNT(*) as count FROM " . MAIN_DB_PREFIX . "a_predmet";
            $resql = $db->query($sql);
            if ($resql && $obj = $db->fetch_object($resql)) {
                $report['total_predmeti'] = (int)$obj->count;
            }

            // Sample check of first 10 predmeti for sync status
            $sql = "SELECT ID_predmeta FROM " . MAIN_DB_PREFIX . "a_predmet LIMIT 10";
            $resql = $db->query($sql);
            if ($resql) {
                while ($obj = $db->fetch_object($resql)) {
                    $status = self::getSyncStatus($db, $conf, $obj->ID_predmeta);
                    if (!$status['sync_needed']) {
                        $report['synced_predmeti']++;
                    } else {
                        $report['sync_issues'][] = [
                            'predmet_id' => $obj->ID_predmeta,
                            'issue' => 'File count mismatch'
                        ];
                    }
                }
            }

            return $report;

        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }
}