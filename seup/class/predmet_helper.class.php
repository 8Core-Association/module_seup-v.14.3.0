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

class Predmet_helper
{
    /**
     * Create SEUP database tables if they don't exist
     */
    public static function createSeupDatabaseTables($db)
    {
        $sql_tables = [
            "CREATE TABLE IF NOT EXISTS " . MAIN_DB_PREFIX . "a_oznaka_ustanove (
                ID_ustanove int(11) NOT NULL AUTO_INCREMENT,
                singleton tinyint(1) DEFAULT 1,
                code_ustanova varchar(20) NOT NULL,
                name_ustanova varchar(255) NOT NULL,
                PRIMARY KEY (ID_ustanove),
                UNIQUE KEY singleton (singleton)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8",

            "CREATE TABLE IF NOT EXISTS " . MAIN_DB_PREFIX . "a_klasifikacijska_oznaka (
                ID_klasifikacijske_oznake int(11) NOT NULL AUTO_INCREMENT,
                ID_ustanove int(11) NOT NULL,
                klasa_broj varchar(10) NOT NULL,
                sadrzaj varchar(10) NOT NULL,
                dosje_broj varchar(10) NOT NULL,
                vrijeme_cuvanja int(11) NOT NULL DEFAULT 0,
                opis_klasifikacijske_oznake text,
                PRIMARY KEY (ID_klasifikacijske_oznake),
                UNIQUE KEY unique_combination (klasa_broj, sadrzaj, dosje_broj),
                KEY fk_ustanova (ID_ustanove)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8",

            "CREATE TABLE IF NOT EXISTS " . MAIN_DB_PREFIX . "a_interna_oznaka_korisnika (
                ID int(11) NOT NULL AUTO_INCREMENT,
                ID_ustanove int(11) NOT NULL,
                ime_prezime varchar(255) NOT NULL,
                rbr int(11) NOT NULL,
                naziv varchar(255) NOT NULL,
                PRIMARY KEY (ID),
                UNIQUE KEY unique_rbr (rbr),
                KEY fk_ustanova_korisnik (ID_ustanove)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8",

            "CREATE TABLE IF NOT EXISTS " . MAIN_DB_PREFIX . "a_predmet (
                ID_predmeta int(11) NOT NULL AUTO_INCREMENT,
                klasa_br varchar(10) NOT NULL,
                sadrzaj varchar(10) NOT NULL,
                dosje_broj varchar(10) NOT NULL,
                godina varchar(2) NOT NULL,
                predmet_rbr int(11) NOT NULL,
                naziv_predmeta text NOT NULL,
                ID_ustanove int(11) NOT NULL,
                ID_interna_oznaka_korisnika int(11) NOT NULL,
                ID_klasifikacijske_oznake int(11) NOT NULL,
                vrijeme_cuvanja int(11) NOT NULL,
                tstamp_created timestamp DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (ID_predmeta),
                UNIQUE KEY unique_predmet (klasa_br, sadrzaj, dosje_broj, godina, predmet_rbr),
                KEY fk_ustanova_predmet (ID_ustanove),
                KEY fk_korisnik_predmet (ID_interna_oznaka_korisnika),
                KEY fk_klasifikacija_predmet (ID_klasifikacijske_oznake)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8",

            "CREATE TABLE IF NOT EXISTS " . MAIN_DB_PREFIX . "a_tagovi (
                rowid int(11) NOT NULL AUTO_INCREMENT,
                tag varchar(100) NOT NULL,
                color varchar(20) DEFAULT 'blue',
                entity int(11) NOT NULL DEFAULT 1,
                date_creation datetime NOT NULL,
                fk_user_creat int(11) NOT NULL,
                PRIMARY KEY (rowid),
                UNIQUE KEY unique_tag_entity (tag, entity)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8",

            "CREATE TABLE IF NOT EXISTS " . MAIN_DB_PREFIX . "a_predmet_tagovi (
                rowid int(11) NOT NULL AUTO_INCREMENT,
                fk_predmet int(11) NOT NULL,
                fk_tag int(11) NOT NULL,
                PRIMARY KEY (rowid),
                UNIQUE KEY unique_predmet_tag (fk_predmet, fk_tag),
                KEY fk_predmet_idx (fk_predmet),
                KEY fk_tag_idx (fk_tag)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8",

            "CREATE TABLE IF NOT EXISTS " . MAIN_DB_PREFIX . "a_predmet_stranka (
                rowid int(11) NOT NULL AUTO_INCREMENT,
                ID_predmeta int(11) NOT NULL,
                fk_soc int(11) NOT NULL,
                role varchar(50) DEFAULT 'creator',
                date_stranka_opened datetime DEFAULT NULL,
                PRIMARY KEY (rowid),
                KEY fk_predmet_stranka (ID_predmeta),
                KEY fk_soc_stranka (fk_soc)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8",

            "CREATE TABLE IF NOT EXISTS " . MAIN_DB_PREFIX . "a_arhiva (
                ID_arhive int(11) NOT NULL AUTO_INCREMENT,
                ID_predmeta int(11) NOT NULL,
                klasa_predmeta varchar(50) NOT NULL,
                naziv_predmeta text NOT NULL,
                lokacija_arhive varchar(500) NOT NULL,
                broj_dokumenata int(11) DEFAULT 0,
                razlog_arhiviranja text,
                datum_arhiviranja timestamp DEFAULT CURRENT_TIMESTAMP,
                fk_user_arhivirao int(11) NOT NULL,
                status_arhive enum('active','deleted') DEFAULT 'active',
                PRIMARY KEY (ID_arhive),
                KEY fk_predmet_arhiva (ID_predmeta),
                KEY fk_user_arhiva (fk_user_arhivirao)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8"
        ];

        foreach ($sql_tables as $sql) {
            $resql = $db->query($sql);
            if (!$resql) {
                dol_syslog("Error creating table: " . $db->lasterror(), LOG_ERR);
            }
        }
    }

    /**
     * Generate sanitized folder name from klasa and opis
     */
    public static function generateFolderName($klasa_br, $sadrzaj, $dosje_broj, $godina, $predmet_rbr, $naziv_predmeta)
    {
        // Create klasa format: 010-05_25-12_4 (replace / with _ for folder name)
        $klasa_format = $klasa_br . '-' . $sadrzaj . '_' . $godina . '-' . $dosje_broj . '_' . $predmet_rbr;
        
        // Sanitize naziv_predmeta for folder name
        $sanitized_naziv = self::sanitizeForFolder($naziv_predmeta);
        
        // Combine klasa and naziv with separator
        $folder_name = $klasa_format . '-' . $sanitized_naziv;
        
        // Ensure folder name is not too long (max 200 chars for safety)
        if (strlen($folder_name) > 200) {
            $sanitized_naziv = substr($sanitized_naziv, 0, 200 - strlen($klasa_format) - 1);
            $folder_name = $klasa_format . '-' . $sanitized_naziv;
        }
        
        return $folder_name;
    }

    /**
     * Sanitize string for use in folder names
     */
    public static function sanitizeForFolder($string)
    {
        // Remove or replace problematic characters
        $string = trim($string);
        
        // Replace Croatian characters
        $croatian_chars = [
            'č' => 'c', 'ć' => 'c', 'đ' => 'd', 'š' => 's', 'ž' => 'z',
            'Č' => 'C', 'Ć' => 'C', 'Đ' => 'D', 'Š' => 'S', 'Ž' => 'Z'
        ];
        $string = strtr($string, $croatian_chars);
        
        // Replace spaces and special characters with underscores
        $string = preg_replace('/[^a-zA-Z0-9\-_]/', '_', $string);
        
        // Remove multiple consecutive underscores
        $string = preg_replace('/_+/', '_', $string);
        
        // Remove leading/trailing underscores
        $string = trim($string, '_');
        
        return $string;
    }

    /**
     * Get predmet folder path
     */
    public static function getPredmetFolderPath($predmet_id, $db)
    {
        // Fetch predmet details
        $sql = "SELECT 
                    p.klasa_br,
                    p.sadrzaj,
                    p.dosje_broj,
                    p.godina,
                    p.predmet_rbr,
                    p.naziv_predmeta
                FROM " . MAIN_DB_PREFIX . "a_predmet p
                WHERE p.ID_predmeta = " . (int)$predmet_id;

        $resql = $db->query($sql);
        if ($resql && $obj = $db->fetch_object($resql)) {
            $folder_name = self::generateFolderName(
                $obj->klasa_br,
                $obj->sadrzaj,
                $obj->dosje_broj,
                $obj->godina,
                $obj->predmet_rbr,
                $obj->naziv_predmeta
            );
            
            // Add year folder structure: SEUP/Predmeti/2025/010-05_25-12_6-Naziv/
            $full_year = '20' . $obj->godina;
            return 'SEUP/Predmeti/' . $full_year . '/' . $folder_name . '/';
        }
        
        // Fallback to old format if predmet not found
        return 'SEUP/predmet_' . $predmet_id . '/';
    }

    /**
     * Create predmet directory
     */
    public static function createPredmetDirectory($predmet_id, $db, $conf)
    {
        $relative_path = self::getPredmetFolderPath($predmet_id, $db);
        $full_path = DOL_DATA_ROOT . '/ecm/' . $relative_path;
        
        if (!is_dir($full_path)) {
            if (!dol_mkdir($full_path)) {
                dol_syslog("Failed to create directory: " . $full_path, LOG_ERR);
                return false;
            }
            dol_syslog("Created directory: " . $full_path, LOG_INFO);
        }
        
        return $relative_path;
    }

    /**
     * Fetch dropdown data for forms
     */
    public static function fetchDropdownData($db, $langs, &$klasaOptions, &$klasaMapJson, &$zaposlenikOptions)
    {
        // Fetch klasa options
        $sql = "SELECT DISTINCT klasa_broj FROM " . MAIN_DB_PREFIX . "a_klasifikacijska_oznaka ORDER BY klasa_broj ASC";
        $resql = $db->query($sql);
        $klasaOptions = '<option value="">Odaberite klasu</option>';
        if ($resql) {
            while ($obj = $db->fetch_object($resql)) {
                $klasaOptions .= '<option value="' . $obj->klasa_broj . '">' . $obj->klasa_broj . '</option>';
            }
        }

        // Build klasa map for JavaScript
        $klasaMap = [];
        $sql = "SELECT klasa_broj, sadrzaj, dosje_broj FROM " . MAIN_DB_PREFIX . "a_klasifikacijska_oznaka ORDER BY klasa_broj, sadrzaj, dosje_broj";
        $resql = $db->query($sql);
        if ($resql) {
            while ($obj = $db->fetch_object($resql)) {
                if (!isset($klasaMap[$obj->klasa_broj])) {
                    $klasaMap[$obj->klasa_broj] = [];
                }
                if (!isset($klasaMap[$obj->klasa_broj][$obj->sadrzaj])) {
                    $klasaMap[$obj->klasa_broj][$obj->sadrzaj] = [];
                }
                $klasaMap[$obj->klasa_broj][$obj->sadrzaj][] = $obj->dosje_broj;
            }
        }
        $klasaMapJson = json_encode($klasaMap);

        // Fetch zaposlenik options
        $sql = "SELECT ID, ime_prezime FROM " . MAIN_DB_PREFIX . "a_interna_oznaka_korisnika ORDER BY ime_prezime ASC";
        $resql = $db->query($sql);
        $zaposlenikOptions = '<option value="">Odaberite zaposlenika</option>';
        if ($resql) {
            while ($obj = $db->fetch_object($resql)) {
                $zaposlenikOptions .= '<option value="' . $obj->ID . '">' . htmlspecialchars($obj->ime_prezime) . '</option>';
            }
        }
    }

    /**
     * Get next predmet sequential number
     */
    public static function getNextPredmetRbr($db, $klasa_br, $sadrzaj, $dosje_br, $god)
    {
        $sql = "SELECT MAX(predmet_rbr) as max_rbr 
                FROM " . MAIN_DB_PREFIX . "a_predmet 
                WHERE klasa_br = '" . $db->escape($klasa_br) . "'
                AND sadrzaj = '" . $db->escape($sadrzaj) . "'
                AND dosje_broj = '" . $db->escape($dosje_br) . "'
                AND godina = '" . $db->escape($god) . "'";

        $resql = $db->query($sql);
        if ($resql && $obj = $db->fetch_object($resql)) {
            return ($obj->max_rbr ? $obj->max_rbr + 1 : 1);
        }
        return 1;
    }

    /**
     * Check if predmet exists
     */
    public static function checkPredmetExists($db, $klasa_br, $sadrzaj, $dosje_br, $god)
    {
        $sql = "SELECT COUNT(*) as count 
                FROM " . MAIN_DB_PREFIX . "a_predmet 
                WHERE klasa_br = '" . $db->escape($klasa_br) . "'
                AND sadrzaj = '" . $db->escape($sadrzaj) . "'
                AND dosje_broj = '" . $db->escape($dosje_br) . "'
                AND godina = '" . $db->escape($god) . "'";

        $resql = $db->query($sql);
        if ($resql && $obj = $db->fetch_object($resql)) {
            return $obj->count > 0;
        }
        return false;
    }

    /**
     * Get klasifikacijska oznaka details
     */
    public static function getKlasifikacijskaOznaka($db, $klasa_br, $sadrzaj, $dosje_br)
    {
        $sql = "SELECT ID_klasifikacijske_oznake, vrijeme_cuvanja, opis_klasifikacijske_oznake
                FROM " . MAIN_DB_PREFIX . "a_klasifikacijska_oznaka 
                WHERE klasa_broj = '" . $db->escape($klasa_br) . "'
                AND sadrzaj = '" . $db->escape($sadrzaj) . "'
                AND dosje_broj = '" . $db->escape($dosje_br) . "'";

        $resql = $db->query($sql);
        if ($resql && $obj = $db->fetch_object($resql)) {
            return $obj;
        }
        return false;
    }

    /**
     * Get ustanova by zaposlenik
     */
    public static function getUstanovaByZaposlenik($db, $zaposlenik_id)
    {
        $sql = "SELECT u.ID_ustanove, u.code_ustanova, u.name_ustanova
                FROM " . MAIN_DB_PREFIX . "a_oznaka_ustanove u
                INNER JOIN " . MAIN_DB_PREFIX . "a_interna_oznaka_korisnika k ON u.ID_ustanove = k.ID_ustanove
                WHERE k.ID = " . (int)$zaposlenik_id;

        $resql = $db->query($sql);
        if ($resql && $obj = $db->fetch_object($resql)) {
            return $obj;
        }
        return false;
    }

    /**
     * Insert new predmet with new folder structure
     */
    public static function insertPredmet($db, $klasa_br, $sadrzaj, $dosje_br, $god, $rbr_predmeta, $naziv, $id_ustanove, $id_zaposlenik, $id_klasifikacijske_oznake, $vrijeme_cuvanja)
    {
        $sql = "INSERT INTO " . MAIN_DB_PREFIX . "a_predmet (
                    klasa_br, sadrzaj, dosje_broj, godina, predmet_rbr, naziv_predmeta,
                    ID_ustanove, ID_interna_oznaka_korisnika, ID_klasifikacijske_oznake,
                    vrijeme_cuvanja, tstamp_created
                ) VALUES (
                    '" . $db->escape($klasa_br) . "',
                    '" . $db->escape($sadrzaj) . "',
                    '" . $db->escape($dosje_br) . "',
                    '" . $db->escape($god) . "',
                    " . (int)$rbr_predmeta . ",
                    '" . $db->escape($naziv) . "',
                    " . (int)$id_ustanove . ",
                    " . (int)$id_zaposlenik . ",
                    " . (int)$id_klasifikacijske_oznake . ",
                    " . (int)$vrijeme_cuvanja . ",
                    NOW()
                )";

        return $db->query($sql);
    }

    /**
     * Fetch uploaded documents for a predmet
     */
    public static function fetchUploadedDocuments($db, $conf, &$documentTableHTML, $langs, $caseId)
    {
        // Auto-scan ECM if enabled
        if (getDolGlobalString('SEUP_ECM_AUTO_SCAN', '0') === '1') {
            require_once __DIR__ . '/ecm_scanner.class.php';
            $scanResult = ECM_Scanner::scanPredmetFolder($db, $conf, $GLOBALS['user'], $caseId);
            if ($scanResult['success'] && $scanResult['files_added'] > 0) {
                dol_syslog("Auto-scan added " . $scanResult['files_added'] . " files to ECM", LOG_INFO);
            }
        }
        
        // Get documents from both Dolibarr ECM and Nextcloud
        $documents = self::getCombinedDocuments($db, $conf, $caseId);

        if (count($documents) > 0) {
            $documentTableHTML = '<table class="table table-sm table-bordered">';
            $documentTableHTML .= '<thead class="table-dark">';
            $documentTableHTML .= '<tr>';
            $documentTableHTML .= '<th>Naziv datoteke</th>';
            $documentTableHTML .= '<th>Veličina</th>';
            $documentTableHTML .= '<th>Datum</th>';
            $documentTableHTML .= '<th>Kreirao</th>';
            $documentTableHTML .= '<th>Akcije</th>';
            $documentTableHTML .= '</tr>';
            $documentTableHTML .= '</thead>';
            $documentTableHTML .= '<tbody>';

            foreach ($documents as $doc) {
                // Handle different document sources
                if (isset($doc->source) && $doc->source === 'nextcloud') {
                    if ($doc->edit_url) {
                        $documentTableHTML .= '<a href="' . $doc->edit_url . '" class="seup-document-action-btn seup-document-btn-edit" target="_blank" title="Uredi u Nextcloud">';
                        $documentTableHTML .= '<i class="fas fa-edit"></i>';
                        $documentTableHTML .= '</a>';
                    }
                } else {
                    // No edit button for Dolibarr ECM documents for now
                }
                
                $documentTableHTML .= '<tr>';
                $documentTableHTML .= '<td>';
                $documentTableHTML .= '<i class="' . self::getFileIcon($doc->filename) . ' me-2"></i>';
                $documentTableHTML .= htmlspecialchars($doc->filename);
                if (isset($doc->tags) && !empty($doc->tags)) {
                    $documentTableHTML .= '<br><small class="text-muted"><i class="fas fa-tags"></i> ' . htmlspecialchars($doc->tags) . '</small>';
                }
                $documentTableHTML .= '</td>';
                
                // File size
                $file_size = 'N/A';
                if (isset($doc->size) && $doc->size > 0) {
                    $file_size = self::formatFileSize($doc->size);
                } elseif (isset($doc->filepath)) {
                    $full_path = DOL_DATA_ROOT . '/ecm/' . rtrim($doc->filepath, '/') . '/' . $doc->filename;
                    if (file_exists($full_path)) {
                        $file_size = self::formatFileSize(filesize($full_path));
                    }
                }
                $documentTableHTML .= '<td><span class="seup-document-size">' . $file_size . '</span></td>';
                
                // Date formatting
                $date_formatted = 'N/A';
                if (isset($doc->date_c)) {
                    $date_formatted = date('d.m.Y H:i', (int)$doc->date_c);
                } elseif (isset($doc->last_modified)) {
                    $date_formatted = date('d.m.Y H:i', strtotime($doc->last_modified));
                }
                $documentTableHTML .= '<td><div class="seup-document-date"><i class="fas fa-calendar me-1"></i>' . $date_formatted . '</div></td>';
                
                // Created by
                $created_by = $doc->created_by ?? 'N/A';
                $documentTableHTML .= '<td><div class="seup-document-user"><i class="fas fa-user me-1"></i>' . htmlspecialchars($created_by) . '</div></td>';
                
                $documentTableHTML .= '<td>';
                $documentTableHTML .= '<div class="seup-document-actions">';
                
                // Download button
                $download_url = DOL_URL_ROOT . '/document.php?modulepart=ecm&file=' . urlencode($relative_path . $doc->filename);
                $documentTableHTML .= '<a href="' . $download_url . '" class="seup-document-btn seup-document-btn-download" target="_blank" title="Preuzmi">';
                $documentTableHTML .= '<i class="fas fa-download"></i>';
                $documentTableHTML .= '</a>';
                
                // Edit button (if available)
                if (isset($doc->edit_url) && !empty($doc->edit_url)) {
                    $documentTableHTML .= '<a href="' . $doc->edit_url . '" class="seup-document-btn seup-document-btn-edit" target="_blank" title="Uredi u Nextcloud">';
                    $documentTableHTML .= '<i class="fas fa-edit"></i>';
                    $documentTableHTML .= '</a>';
                }
                
                // Delete button
                $documentTableHTML .= '<button class="seup-document-btn seup-document-btn-delete delete-document-btn" ';
                $documentTableHTML .= 'data-filename="' . htmlspecialchars($doc->filename) . '" ';
                $documentTableHTML .= 'data-filepath="' . htmlspecialchars($doc->filepath ?? $relative_path) . '" ';
                $documentTableHTML .= 'title="Obriši dokument">';
                $documentTableHTML .= '<i class="fas fa-trash"></i>';
                $documentTableHTML .= '</button>';
                
                // Additional Nextcloud indicators
                if (isset($doc->comments_count) && $doc->comments_count > 0) {
                    $documentTableHTML .= '<span class="seup-document-badge seup-badge-info" title="Komentari"><i class="fas fa-comments"></i> ' . $doc->comments_count . '</span>';
                }
                if (isset($doc->is_shared) && $doc->is_shared) {
                    $documentTableHTML .= '<span class="seup-document-badge seup-badge-warning" title="Dijeljeno"><i class="fas fa-share-alt"></i></span>';
                }
                
                $documentTableHTML .= '</div>'; // seup-document-actions
                $documentTableHTML .= '</td>';
                $documentTableHTML .= '</tr>';
            }

            $documentTableHTML .= '</tbody>';
            $documentTableHTML .= '</table>';
        } else {
            $documentTableHTML = '<div class="alert alert-info">';
            $documentTableHTML .= '<i class="fas fa-info-circle me-2"></i>';
            $documentTableHTML .= $langs->trans("NoDocumentsFound");
            $documentTableHTML .= '</div>';
        }
    }

    /**
     * Get combined documents from both Dolibarr ECM and Nextcloud
     * Optimized for ECM-Nextcloud mount scenarios
     */
    public static function getCombinedDocuments($db, $conf, $caseId)
    {
        $allDocuments = [];
        
        // 1. Get documents from Dolibarr ECM
        $relative_path = self::getPredmetFolderPath($caseId, $db);
        $search_paths = [
            rtrim($relative_path, '/'),
            $relative_path
        ];
        
        $sql_conditions = [];
        foreach ($search_paths as $path) {
            $sql_conditions[] = "ef.filepath = '" . $db->escape($path) . "'";
        }
        
        $sql = "SELECT 
                    ef.rowid,
                    ef.filename,
                    ef.filepath,
                    ef.date_c,
                    CONCAT(u.firstname, ' ', u.lastname) as created_by
                FROM " . MAIN_DB_PREFIX . "ecm_files ef
                LEFT JOIN " . MAIN_DB_PREFIX . "user u ON ef.fk_user_c = u.rowid
                WHERE (" . implode(' OR ', $sql_conditions) . ")
                AND ef.entity = " . $conf->entity . "
                ORDER BY ef.date_c DESC";

        $resql = $db->query($sql);
        if ($resql) {
            while ($obj = $db->fetch_object($resql)) {
                $obj->source = 'dolibarr';
                $allDocuments[] = $obj;
            }
        }
        
        // 2. Get additional Nextcloud metadata (only if ECM is not Nextcloud mounted)
        try {
            require_once __DIR__ . '/nextcloud_api.class.php';
            $nextcloudApi = new NextcloudAPI($db, $conf);
            
            if (!$nextcloudApi->isECMNextcloudMounted()) {
                // Traditional separate Nextcloud storage
                $nextcloudFiles = $nextcloudApi->getFilesFromFolder($relative_path);
                
                foreach ($nextcloudFiles as $file) {
                    // Convert to object format similar to ECM
                    $fileObj = new stdClass();
                    $fileObj->filename = $file['filename'];
                    $fileObj->size = $file['size'];
                    $fileObj->last_modified = $file['last_modified'];
                    $fileObj->download_url = $file['download_url'];
                    $fileObj->edit_url = $file['edit_url'];
                    $fileObj->tags = $file['tags'];
                    $fileObj->comments_count = $file['comments_count'];
                    $fileObj->is_shared = $file['is_shared'];
                    $fileObj->source = 'nextcloud';
                    
                    $allDocuments[] = $fileObj;
                }
            } else {
                // ECM is Nextcloud mounted - enhance ECM records with Nextcloud metadata
                $nextcloudFiles = $nextcloudApi->getFilesFromFolder($relative_path);
                
                // Enhance existing ECM records with Nextcloud metadata
                foreach ($allDocuments as $ecmDoc) {
                    foreach ($nextcloudFiles as $ncFile) {
                        if ($ecmDoc->filename === $ncFile['filename']) {
                            // Add Nextcloud-specific metadata to ECM record
                            $ecmDoc->nextcloud_tags = $ncFile['tags'];
                            $ecmDoc->nextcloud_comments = $ncFile['comments_count'];
                            $ecmDoc->nextcloud_shared = $ncFile['is_shared'];
                            $ecmDoc->edit_url = $ncFile['edit_url'];
                            $ecmDoc->enhanced_with_nextcloud = true;
                            break;
                        }
                    }
                }
            }
        } catch (Exception $e) {
            dol_syslog("Error fetching Nextcloud documents: " . $e->getMessage(), LOG_WARNING);
        }
        
        // Sort combined documents by date (newest first)
        usort($allDocuments, function($a, $b) {
            if (isset($a->date_c) && isset($b->date_c)) {
                return $b->date_c - $a->date_c;
            } elseif (isset($a->date_c)) {
                return -1;
            } elseif (isset($b->date_c)) {
                return 1;
            } else {
                // Both are Nextcloud files, compare by last_modified
                return strtotime($b->last_modified) - strtotime($a->last_modified);
            }
        });
        
        return $allDocuments;
    }

    /**
     * Format file size in human readable format
     */
    public static function formatFileSize($bytes)
    {
        if ($bytes == 0) return '0 B';
        
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $factor = floor(log($bytes, 1024));
        
        return sprintf("%.1f %s", $bytes / pow(1024, $factor), $units[$factor]);
    }

    /**
     * Get appropriate icon for file type
     */
    public static function getFileIcon($filename)
    {
        $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        
        $iconMap = [
            'pdf' => 'fas fa-file-pdf text-danger',
            'doc' => 'fas fa-file-word text-primary',
            'docx' => 'fas fa-file-word text-primary',
            'xls' => 'fas fa-file-excel text-success',
            'xlsx' => 'fas fa-file-excel text-success',
            'ppt' => 'fas fa-file-powerpoint text-warning',
            'pptx' => 'fas fa-file-powerpoint text-warning',
            'jpg' => 'fas fa-file-image text-info',
            'jpeg' => 'fas fa-file-image text-info',
            'png' => 'fas fa-file-image text-info',
            'gif' => 'fas fa-file-image text-info',
            'txt' => 'fas fa-file-alt text-secondary',
            'zip' => 'fas fa-file-archive text-dark',
            'rar' => 'fas fa-file-archive text-dark'
        ];
        
        return $iconMap[$extension] ?? 'fas fa-file text-muted';
    }

    /**
     * Archive predmet and move documents
     */
    public static function archivePredmet($db, $conf, $user, $predmet_id, $razlog = '')
    {
        try {
            $db->begin();

            // Get predmet details
            $sql = "SELECT 
                        p.klasa_br, p.sadrzaj, p.dosje_broj, p.godina, p.predmet_rbr,
                        p.naziv_predmeta
                    FROM " . MAIN_DB_PREFIX . "a_predmet p
                    WHERE p.ID_predmeta = " . (int)$predmet_id;

            $resql = $db->query($sql);
            if (!$resql || !($predmet = $db->fetch_object($resql))) {
                throw new Exception("Predmet not found");
            }

            $klasa = $predmet->klasa_br . '-' . $predmet->sadrzaj . '/' . 
                     $predmet->godina . '-' . $predmet->dosje_broj . '/' . 
                     $predmet->predmet_rbr;

            // Generate archive location
            $archive_location = 'ecm/SEUP/Arhiva/' . self::generateFolderName(
                $predmet->klasa_br,
                $predmet->sadrzaj,
                $predmet->dosje_broj,
                $predmet->godina,
                $predmet->predmet_rbr,
                $predmet->naziv_predmeta
            ) . '/';

            // Count documents
            $current_path = self::getPredmetFolderPath($predmet_id, $db);
            $sql = "SELECT COUNT(*) as count FROM " . MAIN_DB_PREFIX . "ecm_files 
                    WHERE filepath = '" . $db->escape($current_path) . "'";
            $resql = $db->query($sql);
            $doc_count = 0;
            if ($resql && $obj = $db->fetch_object($resql)) {
                $doc_count = $obj->count;
            }

            // Create archive record
            $sql = "INSERT INTO " . MAIN_DB_PREFIX . "a_arhiva (
                        ID_predmeta, klasa_predmeta, naziv_predmeta, lokacija_arhive, broj_dokumenata,
                        razlog_arhiviranja, fk_user_arhivirao
                    ) VALUES (
                        " . (int)$predmet_id . ",
                        '" . $db->escape($klasa) . "',
                        '" . $db->escape($predmet->naziv_predmeta) . "',
                        '" . $db->escape($archive_location) . "',
                        " . (int)$doc_count . ",
                        '" . $db->escape($razlog) . "',
                        " . (int)$user->id . "
                    )";

            if (!$db->query($sql)) {
                throw new Exception("Failed to create archive record: " . $db->lasterror());
            }

            // Move documents to archive folder
            $full_year = '20' . $predmet->godina;
            $archive_path = 'SEUP/Arhiva/' . $full_year . '/' . self::generateFolderName(
                $predmet->klasa_br,
                $predmet->sadrzaj,
                $predmet->dosje_broj,
                $predmet->godina,
                $predmet->predmet_rbr,
                $predmet->naziv_predmeta
            ) . '/';
            $current_full_path = DOL_DATA_ROOT . '/ecm/' . $current_path;
            $archive_full_path = DOL_DATA_ROOT . '/ecm/' . $archive_path;

            $files_moved = 0;
            if (is_dir($current_full_path)) {
                // Create archive directory
                if (!is_dir($archive_full_path)) {
                    dol_mkdir($archive_full_path);
                }

                // Move files
                $files = scandir($current_full_path);
                foreach ($files as $file) {
                    if ($file !== '.' && $file !== '..') {
                        $source = $current_full_path . $file;
                        $destination = $archive_full_path . $file;
                        
                        if (rename($source, $destination)) {
                            // Update ECM record
                            $sql = "UPDATE " . MAIN_DB_PREFIX . "ecm_files 
                                    SET filepath = '" . $db->escape($archive_path) . "'
                                    WHERE filepath = '" . $db->escape($current_path) . "'
                                    AND filename = '" . $db->escape($file) . "'";
                            $db->query($sql);
                            $files_moved++;
                        }
                    }
                }

                // Remove empty directory
                if (count(scandir($current_full_path)) === 2) {
                    rmdir($current_full_path);
                }
            }

            $db->commit();
            return [
                'success' => true,
                'message' => 'Predmet uspješno arhiviran',
                'files_moved' => $files_moved
            ];

        } catch (Exception $e) {
            $db->rollback();
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * Restore predmet from archive
     */
    public static function restorePredmet($db, $conf, $user, $arhiva_id)
    {
        try {
            $db->begin();

            // Get archive details
            $sql = "SELECT * FROM " . MAIN_DB_PREFIX . "a_arhiva WHERE ID_arhive = " . (int)$arhiva_id;
            $resql = $db->query($sql);
            if (!$resql || !($arhiva = $db->fetch_object($resql))) {
                throw new Exception("Archive record not found");
            }

            // Get new folder path for restored predmet
            $new_path = self::getPredmetFolderPath($arhiva->ID_predmeta, $db);
            
            // Extract year from klasa_predmeta format (001-01/25-01/1)
            if (preg_match('/\/(\d{2})-/', $arhiva->klasa_predmeta, $matches)) {
                $year = '20' . $matches[1];
                $archive_path = 'SEUP/Arhiva/' . $year . '/' . self::generateFolderName(
                    explode('-', $arhiva->klasa_predmeta)[0],
                    explode('-', explode('/', $arhiva->klasa_predmeta)[0])[1],
                    explode('-', explode('/', $arhiva->klasa_predmeta)[1])[1],
                    $matches[1],
                    explode('/', $arhiva->klasa_predmeta)[2],
                    $arhiva->naziv_predmeta
                ) . '/';
            } else {
                // Fallback for old format
                $archive_path = 'SEUP/Arhiva/' . $arhiva->klasa_predmeta . '/';
            }
            
            $archive_full_path = DOL_DATA_ROOT . '/ecm/' . $archive_path;
            $new_full_path = DOL_DATA_ROOT . '/ecm/' . $new_path;

            $files_moved = 0;
            if (is_dir($archive_full_path)) {
                // Create new directory
                if (!is_dir($new_full_path)) {
                    dol_mkdir($new_full_path);
                }

                // Move files back
                $files = scandir($archive_full_path);
                foreach ($files as $file) {
                    if ($file !== '.' && $file !== '..') {
                        $source = $archive_full_path . $file;
                        $destination = $new_full_path . $file;
                        
                        if (rename($source, $destination)) {
                            // Update ECM record
                            $sql = "UPDATE " . MAIN_DB_PREFIX . "ecm_files 
                                    SET filepath = '" . $db->escape($new_path) . "'
                                    WHERE filepath = '" . $db->escape($archive_path) . "'
                                    AND filename = '" . $db->escape($file) . "'";
                            $db->query($sql);
                            $files_moved++;
                        }
                    }
                }

                // Remove empty archive directory
                if (count(scandir($archive_full_path)) === 2) {
                    rmdir($archive_full_path);
                }
            }

            // Delete archive record
            $sql = "DELETE FROM " . MAIN_DB_PREFIX . "a_arhiva WHERE ID_arhive = " . (int)$arhiva_id;
            if (!$db->query($sql)) {
                throw new Exception("Failed to delete archive record");
            }

            $db->commit();
            return [
                'success' => true,
                'message' => 'Predmet uspješno vraćen',
                'files_moved' => $files_moved
            ];

        } catch (Exception $e) {
            $db->rollback();
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * Delete archive permanently
     */
    public static function deleteArchive($db, $conf, $user, $arhiva_id)
    {
        try {
            $db->begin();

            // Get archive details
            $sql = "SELECT * FROM " . MAIN_DB_PREFIX . "a_arhiva WHERE ID_arhive = " . (int)$arhiva_id;
            $resql = $db->query($sql);
            if (!$resql || !($arhiva = $db->fetch_object($resql))) {
                throw new Exception("Archive record not found");
            }

            // Delete physical files
            // Extract year from klasa_predmeta format for proper path
            if (preg_match('/\/(\d{2})-/', $arhiva->klasa_predmeta, $matches)) {
                $year = '20' . $matches[1];
                $archive_path = 'SEUP/Arhiva/' . $year . '/' . self::generateFolderName(
                    explode('-', $arhiva->klasa_predmeta)[0],
                    explode('-', explode('/', $arhiva->klasa_predmeta)[0])[1],
                    explode('-', explode('/', $arhiva->klasa_predmeta)[1])[1],
                    $matches[1],
                    explode('/', $arhiva->klasa_predmeta)[2],
                    $arhiva->naziv_predmeta
                ) . '/';
            } else {
                // Fallback for old format
                $archive_path = 'SEUP/Arhiva/' . $arhiva->klasa_predmeta . '/';
            }
            $archive_full_path = DOL_DATA_ROOT . '/ecm/' . $archive_path;

            $files_deleted = 0;
            if (is_dir($archive_full_path)) {
                // Delete all files in archive directory
                $files = scandir($archive_full_path);
                foreach ($files as $file) {
                    if ($file !== '.' && $file !== '..') {
                        if (unlink($archive_full_path . $file)) {
                            $files_deleted++;
                        }
                    }
                }
                // Remove the directory itself
                rmdir($archive_full_path);
            }

            // Delete ECM records
            $sql = "DELETE FROM " . MAIN_DB_PREFIX . "ecm_files 
                    WHERE filepath = '" . $db->escape($archive_path) . "'";
            $db->query($sql);

            // Delete predmet record from a_predmet table
            $sql = "DELETE FROM " . MAIN_DB_PREFIX . "a_predmet 
                    WHERE ID_predmeta = " . (int)$arhiva->ID_predmeta;
            if (!$db->query($sql)) {
                throw new Exception("Failed to delete predmet record: " . $db->lasterror());
            }

            // Delete tag associations
            $sql = "DELETE FROM " . MAIN_DB_PREFIX . "a_predmet_tagovi 
                    WHERE fk_predmet = " . (int)$arhiva->ID_predmeta;
            $db->query($sql);

            // Delete stranka associations
            $sql = "DELETE FROM " . MAIN_DB_PREFIX . "a_predmet_stranka 
                    WHERE ID_predmeta = " . (int)$arhiva->ID_predmeta;
            $db->query($sql);
            // Delete archive record
            $sql = "DELETE FROM " . MAIN_DB_PREFIX . "a_arhiva WHERE ID_arhive = " . (int)$arhiva_id;
            if (!$db->query($sql)) {
                throw new Exception("Failed to delete archive record");
            }

            $db->commit();
            return [
                'success' => true,
                'message' => 'Predmet je trajno obrisan',
                'files_deleted' => $files_deleted
            ];

        } catch (Exception $e) {
            $db->rollback();
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * Build ORDER BY clause for predmeti with klasa sorting
     */
    public static function buildOrderByKlasa($sortField, $sortOrder)
    {
        $orderByClause = '';
        
        if ($sortField === 'klasa_br') {
            // Special sorting for klasa to handle the combined format
            $orderByClause = "ORDER BY 
                CAST(p.klasa_br AS UNSIGNED) {$sortOrder},
                CAST(p.sadrzaj AS UNSIGNED) {$sortOrder},
                CAST(p.godina AS UNSIGNED) {$sortOrder},
                CAST(p.dosje_broj AS UNSIGNED) {$sortOrder},
                p.predmet_rbr {$sortOrder}";
        } else {
            $orderByClause = "ORDER BY {$sortField} {$sortOrder}";
        }
        
        return $orderByClause;
    }

    /**
     * Build ORDER BY clause for klasifikacijske oznake
     */
    public static function buildKlasifikacijaOrderBy($sortField, $sortOrder, $tableAlias = '')
    {
        $prefix = $tableAlias ? $tableAlias . '.' : '';
        $orderByClause = '';
        
        if ($sortField === 'klasa_broj') {
            $orderByClause = "ORDER BY 
                CAST({$prefix}klasa_broj AS UNSIGNED) {$sortOrder},
                CAST({$prefix}sadrzaj AS UNSIGNED) {$sortOrder},
                CAST({$prefix}dosje_broj AS UNSIGNED) {$sortOrder}";
        } else {
            $orderByClause = "ORDER BY {$prefix}{$sortField} {$sortOrder}";
        }
        
        return $orderByClause;
    }
}