<?php

/**
 * ECM Scanner Class for SEUP Module
 * Scans filesystem and syncs with ECM database
 * (c) 2025 8Core Association
 */

class ECM_Scanner
{
    /**
     * Scan predmet folder and add missing files to ECM database
     */
    public static function scanPredmetFolder($db, $conf, $user, $predmet_id)
    {
        try {
            require_once DOL_DOCUMENT_ROOT . '/ecm/class/ecmfiles.class.php';
            require_once __DIR__ . '/predmet_helper.class.php';

            $relative_path = Predmet_helper::getPredmetFolderPath($predmet_id, $db);
            $full_path = DOL_DATA_ROOT . '/ecm/' . $relative_path;
            
            if (!is_dir($full_path)) {
                return [
                    'success' => false,
                    'error' => 'Folder does not exist: ' . $relative_path
                ];
            }

            // Get existing files from database
            $existing_files = [];
            $sql = "SELECT filename FROM " . MAIN_DB_PREFIX . "ecm_files 
                    WHERE filepath = '" . $db->escape(rtrim($relative_path, '/')) . "'
                    AND entity = " . $conf->entity;
            
            $resql = $db->query($sql);
            if ($resql) {
                while ($obj = $db->fetch_object($resql)) {
                    $existing_files[] = $obj->filename;
                }
            }

            // Scan filesystem for files
            $filesystem_files = [];
            $allowed_extensions = ['pdf', 'docx', 'xlsx', 'doc', 'xls', 'jpg', 'jpeg', 'png', 'odt'];
            
            $files = scandir($full_path);
            foreach ($files as $file) {
                if ($file === '.' || $file === '..') continue;
                
                $file_path = $full_path . $file;
                if (is_file($file_path)) {
                    $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
                    if (in_array($extension, $allowed_extensions)) {
                        $filesystem_files[] = $file;
                    }
                }
            }

            // Find missing files (in filesystem but not in database)
            $missing_files = array_diff($filesystem_files, $existing_files);
            $added_count = 0;
            $errors = [];

            foreach ($missing_files as $filename) {
                $file_path = $full_path . $filename;
                
                // Create ECM record
                $ecmfile = new EcmFiles($db);
                $ecmfile->filepath = rtrim($relative_path, '/');
                $ecmfile->filename = $filename;
                $ecmfile->label = $filename;
                $ecmfile->entity = $conf->entity;
                $ecmfile->gen_or_uploaded = 'uploaded';
                $ecmfile->description = 'Scanned from filesystem';
                $ecmfile->fk_user_c = $user->id;
                $ecmfile->fk_user_m = $user->id;
                
                // Get file modification time
                $file_mtime = filemtime($file_path);
                $ecmfile->date_c = $file_mtime;
                $ecmfile->date_m = $file_mtime;
                
                $result = $ecmfile->create($user);
                if ($result > 0) {
                    $added_count++;
                    dol_syslog("Added ECM record for file: " . $filename, LOG_INFO);
                } else {
                    $errors[] = "Failed to add: " . $filename . " - " . $ecmfile->error;
                    dol_syslog("Failed to add ECM record: " . $filename . " - " . $ecmfile->error, LOG_ERR);
                }
            }

            return [
                'success' => true,
                'message' => "Scanned folder: {$relative_path}",
                'files_found' => count($filesystem_files),
                'files_in_db' => count($existing_files),
                'files_added' => $added_count,
                'missing_files' => $missing_files,
                'errors' => $errors
            ];

        } catch (Exception $e) {
            dol_syslog("ECM scan error: " . $e->getMessage(), LOG_ERR);
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * Sync predmet files from Nextcloud to ECM database
     */
    public static function syncPredmetFromNextcloud($db, $conf, $user, $predmet_id)
    {
        try {
            if (!$predmet_id) {
                return [
                    'success' => false,
                    'error' => 'Invalid predmet ID',
                    'synced' => 0
                ];
            }

            require_once __DIR__ . '/predmet_helper.class.php';
            require_once DOL_DOCUMENT_ROOT . '/ecm/class/ecmfiles.class.php';

            $relative_path = Predmet_helper::getPredmetFolderPath($predmet_id, $db);
            
            // This method is deprecated - ECM scanner only works with filesystem now
            return ['success' => true, 'message' => 'Nextcloud sync deprecated', 'synced' => 0];

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
     * Scan all SEUP folders and sync with ECM database
     */
    public static function scanAllSeupFolders($db, $conf, $user, $limit = 50)
    {
        try {
            $base_path = DOL_DATA_ROOT . '/ecm/SEUP/Predmeti/';
            
            if (!is_dir($base_path)) {
                return [
                    'success' => false,
                    'error' => 'SEUP base folder does not exist'
                ];
            }

            $total_added = 0;
            $processed_folders = 0;
            $errors = [];

            // Scan year folders (2024, 2025, etc.)
            $year_folders = scandir($base_path);
            foreach ($year_folders as $year_folder) {
                if ($year_folder === '.' || $year_folder === '..' || !is_dir($base_path . $year_folder)) {
                    continue;
                }

                $year_path = $base_path . $year_folder . '/';
                $predmet_folders = scandir($year_path);
                
                foreach ($predmet_folders as $predmet_folder) {
                    if ($predmet_folder === '.' || $predmet_folder === '..' || !is_dir($year_path . $predmet_folder)) {
                        continue;
                    }

                    if ($processed_folders >= $limit) {
                        break 2; // Break out of both loops
                    }

                    // Try to find predmet_id from folder name or database
                    $predmet_id = self::findPredmetIdByFolder($db, $predmet_folder, $year_folder);
                    
                    if ($predmet_id) {
                        $result = self::scanPredmetFolder($db, $conf, $user, $predmet_id);
                        if ($result['success']) {
                            $total_added += $result['files_added'];
                            $processed_folders++;
                        } else {
                            $errors[] = "Folder {$predmet_folder}: " . $result['error'];
                        }
                    }
                }
            }

            return [
                'success' => true,
                'message' => "Processed {$processed_folders} folders, added {$total_added} files",
                'processed_folders' => $processed_folders,
                'total_added' => $total_added,
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
     * Find predmet ID by folder name
     */
    private static function findPredmetIdByFolder($db, $folder_name, $year_folder)
    {
        // Extract year from folder (2024 -> 24)
        $year = substr($year_folder, -2);
        
        // Try to parse folder name format: 010-05_25-12_6-Naziv_predmeta
        if (preg_match('/^(\d{3})-(\d{2})_(\d{2})-(\d{2})_(\d+)-/', $folder_name, $matches)) {
            $klasa_br = $matches[1];
            $sadrzaj = $matches[2];
            $godina = $matches[3];
            $dosje_broj = $matches[4];
            $predmet_rbr = $matches[5];
            
            $sql = "SELECT ID_predmeta FROM " . MAIN_DB_PREFIX . "a_predmet 
                    WHERE klasa_br = '" . $db->escape($klasa_br) . "'
                    AND sadrzaj = '" . $db->escape($sadrzaj) . "'
                    AND godina = '" . $db->escape($godina) . "'
                    AND dosje_broj = '" . $db->escape($dosje_broj) . "'
                    AND predmet_rbr = " . (int)$predmet_rbr;
            
            $resql = $db->query($sql);
            if ($resql && $obj = $db->fetch_object($resql)) {
                return $obj->ID_predmeta;
            }
        }
        
        return null;
    }

    /**
     * Remove orphaned ECM records (files in database but not in filesystem)
     */
    public static function cleanupOrphanedRecords($db, $conf, $dry_run = true)
    {
        try {
            $orphaned_records = [];
            $cleaned_count = 0;

            // Get all SEUP ECM files
            $sql = "SELECT rowid, filepath, filename FROM " . MAIN_DB_PREFIX . "ecm_files 
                    WHERE filepath LIKE 'SEUP%'
                    AND entity = " . $conf->entity;

            $resql = $db->query($sql);
            if ($resql) {
                while ($obj = $db->fetch_object($resql)) {
                    $full_path = DOL_DATA_ROOT . '/ecm/' . $obj->filepath . '/' . $obj->filename;
                    
                    if (!file_exists($full_path)) {
                        $orphaned_records[] = [
                            'rowid' => $obj->rowid,
                            'filepath' => $obj->filepath,
                            'filename' => $obj->filename,
                            'full_path' => $full_path
                        ];

                        // If not dry run, delete the record
                        if (!$dry_run) {
                            $delete_sql = "DELETE FROM " . MAIN_DB_PREFIX . "ecm_files 
                                          WHERE rowid = " . (int)$obj->rowid;
                            if ($db->query($delete_sql)) {
                                $cleaned_count++;
                                dol_syslog("Cleaned orphaned ECM record: " . $obj->filename, LOG_INFO);
                            }
                        }
                    }
                }
            }

            return [
                'success' => true,
                'orphaned_records' => $orphaned_records,
                'orphaned_count' => count($orphaned_records),
                'cleaned_count' => $cleaned_count,
                'dry_run' => $dry_run
            ];

        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * Get scan statistics
     */
    public static function getScanStatistics($db, $conf)
    {
        try {
            $stats = [
                'total_ecm_files' => 0,
                'total_filesystem_files' => 0,
                'missing_in_db' => 0,
                'orphaned_in_db' => 0,
                'last_scan' => null
            ];

            // Count ECM files
            $sql = "SELECT COUNT(*) as count FROM " . MAIN_DB_PREFIX . "ecm_files 
                    WHERE filepath LIKE 'SEUP%' AND entity = " . $conf->entity;
            $resql = $db->query($sql);
            if ($resql && $obj = $db->fetch_object($resql)) {
                $stats['total_ecm_files'] = (int)$obj->count;
            }

            // Count filesystem files (basic count)
            $base_path = DOL_DATA_ROOT . '/ecm/SEUP/';
            if (is_dir($base_path)) {
                $stats['total_filesystem_files'] = self::countFilesRecursive($base_path);
            }

            $stats['missing_in_db'] = max(0, $stats['total_filesystem_files'] - $stats['total_ecm_files']);

            return $stats;

        } catch (Exception $e) {
            return [
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * Count files recursively in directory
     */
    private static function countFilesRecursive($dir)
    {
        $count = 0;
        $allowed_extensions = ['pdf', 'docx', 'xlsx', 'doc', 'xls', 'jpg', 'jpeg', 'png', 'odt'];
        
        if (is_dir($dir)) {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS)
            );
            
            foreach ($iterator as $file) {
                if ($file->isFile()) {
                    $extension = strtolower($file->getExtension());
                    if (in_array($extension, $allowed_extensions)) {
                        $count++;
                    }
                }
            }
        }
        
        return $count;
    }
}