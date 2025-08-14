<?php

/**
 * Digital Signature Helper Class for SEUP Module
 * Detects and validates digital signatures in PDF documents
 * (c) 2025 8Core Association
 */

class Digital_Signature_Helper
{
    /**
     * Check if PDF document has digital signature
     */
    public static function checkDigitalSignature($pdfPath)
    {
        try {
            if (!file_exists($pdfPath)) {
                return false;
            }

            $content = file_get_contents($pdfPath);
            if ($content === false) {
                return false;
            }

            // Check for digital signature indicators
            $hasSignature = (
                strpos($content, '/ByteRange') !== false &&
                strpos($content, '/SubFilter') !== false &&
                (strpos($content, 'adbe.pkcs7') !== false || 
                 strpos($content, 'ETSI.CAdES') !== false ||
                 strpos($content, '/Type/Sig') !== false)
            );

            return $hasSignature;

        } catch (Exception $e) {
            dol_syslog("Error checking digital signature: " . $e->getMessage(), LOG_ERR);
            return false;
        }
    }

    /**
     * Get detailed signature information from PDF
     */
    public static function getSignatureDetails($pdfPath)
    {
        try {
            if (!file_exists($pdfPath)) {
                return null;
            }

            $content = file_get_contents($pdfPath);
            if ($content === false) {
                return null;
            }

            $details = [
                'has_signature' => false,
                'signature_type' => null,
                'signer_name' => null,
                'signature_date' => null,
                'certificate_issuer' => null
            ];

            // Check for signature presence
            if (strpos($content, '/ByteRange') === false || strpos($content, '/SubFilter') === false) {
                return $details;
            }

            $details['has_signature'] = true;

            // Extract signature type
            if (strpos($content, 'adbe.pkcs7.detached') !== false) {
                $details['signature_type'] = 'PKCS#7 Detached';
            } elseif (strpos($content, 'adbe.pkcs7.sha1') !== false) {
                $details['signature_type'] = 'PKCS#7 SHA1';
            } elseif (strpos($content, 'ETSI.CAdES.detached') !== false) {
                $details['signature_type'] = 'CAdES Detached';
            }

            // Try to extract signer name (basic extraction)
            if (preg_match('/\/Name\(([^)]+)\)/', $content, $matches)) {
                $details['signer_name'] = self::decodePdfString($matches[1]);
            }

            // Try to extract signature date
            if (preg_match('/\/M\(D:(\d{14}[^)]*)\)/', $content, $matches)) {
                $details['signature_date'] = self::parsePdfDate($matches[1]);
            }

            return $details;

        } catch (Exception $e) {
            dol_syslog("Error getting signature details: " . $e->getMessage(), LOG_ERR);
            return null;
        }
    }

    /**
     * Decode PDF string encoding
     */
    private static function decodePdfString($pdfString)
    {
        // Handle Unicode encoding
        if (substr($pdfString, 0, 2) === 'þÿ') {
            return mb_convert_encoding(substr($pdfString, 2), 'UTF-8', 'UTF-16BE');
        }
        
        // Handle basic PDF string
        return $pdfString;
    }

    /**
     * Parse PDF date format (D:YYYYMMDDHHmmSSOHH'mm')
     */
    private static function parsePdfDate($pdfDate)
    {
        try {
            // Extract basic date part (YYYYMMDDHHMMSS)
            $dateStr = substr($pdfDate, 0, 14);
            
            if (strlen($dateStr) >= 8) {
                $year = substr($dateStr, 0, 4);
                $month = substr($dateStr, 4, 2);
                $day = substr($dateStr, 6, 2);
                $hour = strlen($dateStr) >= 10 ? substr($dateStr, 8, 2) : '00';
                $minute = strlen($dateStr) >= 12 ? substr($dateStr, 10, 2) : '00';
                $second = strlen($dateStr) >= 14 ? substr($dateStr, 12, 2) : '00';
                
                return "$year-$month-$day $hour:$minute:$second";
            }
            
            return null;
        } catch (Exception $e) {
            return null;
        }
    }

    /**
     * Update document signature status in database
     */
    public static function updateDocumentSignatureStatus($db, $conf, $ecm_file_id, $has_signature, $signature_details = null)
    {
        try {
            // Check if signature info table exists, create if not
            self::createSignatureTable($db);

            // Delete existing record
            $sql = "DELETE FROM " . MAIN_DB_PREFIX . "a_document_signatures 
                    WHERE fk_ecm_file = " . (int)$ecm_file_id;
            $db->query($sql);

            // Insert new record if document has signature
            if ($has_signature) {
                $sql = "INSERT INTO " . MAIN_DB_PREFIX . "a_document_signatures (
                            fk_ecm_file, 
                            has_signature, 
                            signature_type, 
                            signer_name, 
                            signature_date, 
                            certificate_issuer,
                            date_checked,
                            entity
                        ) VALUES (
                            " . (int)$ecm_file_id . ",
                            1,
                            " . ($signature_details['signature_type'] ? "'" . $db->escape($signature_details['signature_type']) . "'" : "NULL") . ",
                            " . ($signature_details['signer_name'] ? "'" . $db->escape($signature_details['signer_name']) . "'" : "NULL") . ",
                            " . ($signature_details['signature_date'] ? "'" . $db->escape($signature_details['signature_date']) . "'" : "NULL") . ",
                            " . ($signature_details['certificate_issuer'] ? "'" . $db->escape($signature_details['certificate_issuer']) . "'" : "NULL") . ",
                            NOW(),
                            " . $conf->entity . "
                        )";
                
                return $db->query($sql);
            }

            return true;

        } catch (Exception $e) {
            dol_syslog("Error updating signature status: " . $e->getMessage(), LOG_ERR);
            return false;
        }
    }

    /**
     * Create signature tracking table
     */
    public static function createSignatureTable($db)
    {
        $sql = "CREATE TABLE IF NOT EXISTS " . MAIN_DB_PREFIX . "a_document_signatures (
                    rowid int(11) NOT NULL AUTO_INCREMENT,
                    fk_ecm_file int(11) NOT NULL,
                    has_signature tinyint(1) DEFAULT 0,
                    signature_type varchar(100) DEFAULT NULL,
                    signer_name varchar(255) DEFAULT NULL,
                    signature_date datetime DEFAULT NULL,
                    certificate_issuer varchar(255) DEFAULT NULL,
                    date_checked timestamp DEFAULT CURRENT_TIMESTAMP,
                    entity int(11) NOT NULL DEFAULT 1,
                    PRIMARY KEY (rowid),
                    UNIQUE KEY unique_ecm_file (fk_ecm_file),
                    KEY fk_ecm_file_idx (fk_ecm_file)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8";

        return $db->query($sql);
    }

    /**
     * Get signature status for ECM file
     */
    public static function getSignatureStatus($db, $ecm_file_id)
    {
        $sql = "SELECT * FROM " . MAIN_DB_PREFIX . "a_document_signatures 
                WHERE fk_ecm_file = " . (int)$ecm_file_id;
        
        $resql = $db->query($sql);
        if ($resql && $obj = $db->fetch_object($resql)) {
            return $obj;
        }
        
        return null;
    }

    /**
     * Scan all PDF documents and update signature status
     */
    public static function scanAllDocumentsForSignatures($db, $conf, $user, $limit = 100)
    {
        try {
            self::createSignatureTable($db);

            // Get all PDF files from ECM
            $sql = "SELECT ef.rowid, ef.filepath, ef.filename 
                    FROM " . MAIN_DB_PREFIX . "ecm_files ef
                    WHERE ef.filename LIKE '%.pdf'
                    AND ef.entity = " . $conf->entity . "
                    AND ef.rowid NOT IN (
                        SELECT fk_ecm_file FROM " . MAIN_DB_PREFIX . "a_document_signatures
                    )
                    LIMIT " . (int)$limit;

            $resql = $db->query($sql);
            $processed = 0;
            $signatures_found = 0;

            if ($resql) {
                while ($obj = $db->fetch_object($resql)) {
                    $full_path = DOL_DATA_ROOT . '/ecm/' . $obj->filepath . '/' . $obj->filename;
                    
                    if (file_exists($full_path)) {
                        $has_signature = self::checkDigitalSignature($full_path);
                        $signature_details = null;
                        
                        if ($has_signature) {
                            $signature_details = self::getSignatureDetails($full_path);
                            $signatures_found++;
                        }
                        
                        self::updateDocumentSignatureStatus(
                            $db, 
                            $conf, 
                            $obj->rowid, 
                            $has_signature, 
                            $signature_details
                        );
                    }
                    
                    $processed++;
                }
            }

            return [
                'success' => true,
                'processed' => $processed,
                'signatures_found' => $signatures_found,
                'message' => "Processed {$processed} documents, found {$signatures_found} with digital signatures"
            ];

        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * Get signature statistics
     */
    public static function getSignatureStatistics($db, $conf)
    {
        try {
            $stats = [
                'total_pdfs' => 0,
                'signed_pdfs' => 0,
                'unsigned_pdfs' => 0,
                'percentage_signed' => 0
            ];

            // Count total PDFs
            $sql = "SELECT COUNT(*) as count FROM " . MAIN_DB_PREFIX . "ecm_files 
                    WHERE filename LIKE '%.pdf' AND entity = " . $conf->entity;
            $resql = $db->query($sql);
            if ($resql && $obj = $db->fetch_object($resql)) {
                $stats['total_pdfs'] = (int)$obj->count;
            }

            // Count signed PDFs
            $sql = "SELECT COUNT(*) as count FROM " . MAIN_DB_PREFIX . "a_document_signatures ds
                    INNER JOIN " . MAIN_DB_PREFIX . "ecm_files ef ON ds.fk_ecm_file = ef.rowid
                    WHERE ds.has_signature = 1 AND ef.entity = " . $conf->entity;
            $resql = $db->query($sql);
            if ($resql && $obj = $db->fetch_object($resql)) {
                $stats['signed_pdfs'] = (int)$obj->count;
            }

            $stats['unsigned_pdfs'] = $stats['total_pdfs'] - $stats['signed_pdfs'];
            
            if ($stats['total_pdfs'] > 0) {
                $stats['percentage_signed'] = round(($stats['signed_pdfs'] / $stats['total_pdfs']) * 100, 1);
            }

            return $stats;

        } catch (Exception $e) {
            return [
                'error' => $e->getMessage()
            ];
        }
    }
}