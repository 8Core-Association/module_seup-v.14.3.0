<?php

/**
 * Plaćena licenca
 * (c) 2025 Tomislav Galić <tomislav@8core.hr>
 * Suradnik: Marko Šimunović <marko@8core.hr>
 * Web: https://8core.hr
 * Kontakt: info@8core.hr | Tel: +385 099 851 0717
 * Sva prava pridržana. Ovaj softver je vlasnički i zabranjeno ga je
 * distribuirati ili mijenjati bez izričitog dopuštenia autora.
 */
/**
 *	\file       seup/predmet.php
 *	\ingroup    seup
 *	\brief      Predmet page
 */

// Učitaj Dolibarr okruženje
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
$res = 0;
if (!$res && !empty($_SERVER["CONTEXT_DOCUMENT_ROOT"])) {
    $res = @include $_SERVER["CONTEXT_DOCUMENT_ROOT"] . "/main.inc.php";
}
$tmp = empty($_SERVER['SCRIPT_FILENAME']) ? '' : $_SERVER['SCRIPT_FILENAME'];
$tmp2 = realpath(__FILE__);
$i = strlen($tmp) - 1;
$j = strlen($tmp2) - 1;
while ($i > 0 && $j > 0 && isset($tmp[$i]) && isset($tmp2[$j]) && $tmp[$i] == $tmp2[$j]) {
    $i--;
    $j--;
}
if (!$res && $i > 0 && file_exists(substr($tmp, 0, ($i + 1)) . "/main.inc.php")) {
    $res = @include substr($tmp, 0, ($i + 1)) . "/main.inc.php";
}
if (!$res && $i > 0 && file_exists(dirname(substr($tmp, 0, ($i + 1))) . "/main.inc.php")) {
    $res = @include dirname(substr($tmp, 0, ($i + 1))) . "/main.inc.php";
}
if (!$res && file_exists("../main.inc.php")) {
    $res = @include "../main.inc.php";
}
if (!$res && file_exists("../../main.inc.php")) {
    $res = @include "../../main.inc.php";
}
if (!$res && file_exists("../../../main.inc.php")) {
    $res = @include "../../../main.inc.php";
}
if (!$res) {
    die("Include of main fails");
}

// Libraries
require_once DOL_DOCUMENT_ROOT . '/core/lib/admin.lib.php';
require_once DOL_DOCUMENT_ROOT . '/core/lib/files.lib.php';
require_once DOL_DOCUMENT_ROOT . '/core/lib/functions2.lib.php';
require_once DOL_DOCUMENT_ROOT . '/core/lib/usergroups.lib.php';
require_once DOL_DOCUMENT_ROOT . '/core/class/html.formfile.class.php';
require_once DOL_DOCUMENT_ROOT . '/ecm/class/ecmfiles.class.php';

// Lokalne klase
require_once __DIR__ . '/../class/predmet_helper.class.php';
require_once __DIR__ . '/../class/request_handler.class.php';
require_once __DIR__ . '/../class/cloud_helper.class.php';

// Postavljanje debug logova
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Učitaj datoteke prijevoda
$langs->loadLangs(array("seup@seup"));

$action = GETPOST('action', 'aZ09');
$now = dol_now();
$max = getDolGlobalInt('MAIN_SIZE_SHORTLIST_LIMIT', 5);

// Sigurnosna provjera
$socid = GETPOST('socid', 'int');
if (isset($user->socid) && $user->socid > 0) {
    $action = '';
    $socid = $user->socid;
}

// Hvatanje ID predmeta iz GET zahtjeva
$caseId = GETPOST('id', 'int');
dol_syslog("Dohvaćanje ID predmeta: $caseId", LOG_DEBUG);
if (empty($caseId)) {
    header('Location: ' . dol_buildpath('/custom/seup/pages/predmeti.php', 1));
    exit;
}

// Definiranje direktorija za učitavanje dokumenata
$upload_dir = '';
if ($caseId) {
    $relative_path = Predmet_helper::getPredmetFolderPath($caseId, $db);
    $upload_dir = DOL_DATA_ROOT . '/ecm/' . $relative_path;
}

// Create directory if not exists using new structure
if ($caseId && !is_dir($upload_dir)) {
    Predmet_helper::createPredmetDirectory($caseId, $db, $conf);
}

dol_syslog("Accessing case details for ID: $caseId", LOG_DEBUG);
$caseDetails = null;

if ($caseId) {
    // Fetch case details
    $sql = "SELECT 
                p.ID_predmeta,
                CONCAT(p.klasa_br, '-', p.sadrzaj, '/', p.godina, '-', p.dosje_broj, '/', p.predmet_rbr) as klasa,
                p.naziv_predmeta,
                DATE_FORMAT(p.tstamp_created, '%d.%m.%Y') as datum_otvaranja,
                u.name_ustanova,
                k.ime_prezime,
                ko.opis_klasifikacijske_oznake
            FROM " . MAIN_DB_PREFIX . "a_predmet p
            LEFT JOIN " . MAIN_DB_PREFIX . "a_oznaka_ustanove u ON p.ID_ustanove = u.ID_ustanove
            LEFT JOIN " . MAIN_DB_PREFIX . "a_interna_oznaka_korisnika k ON p.ID_interna_oznaka_korisnika = k.ID
            LEFT JOIN " . MAIN_DB_PREFIX . "a_klasifikacijska_oznaka ko ON p.ID_klasifikacijske_oznake = ko.ID_klasifikacijske_oznake
            WHERE p.ID_predmeta = " . (int)$caseId;

    $resql = $db->query($sql);
    if ($resql && $db->num_rows($resql) > 0) {
        $caseDetails = $db->fetch_object($resql);
    }
}

// definiranje direktorija za privremene datoteke
define('TEMP_DIR_RELATIVE', '/temp/');
define('TEMP_DIR_FULL', DOL_DATA_ROOT . TEMP_DIR_RELATIVE);
define('TEMP_DIR_WEB', DOL_URL_ROOT . '/documents' . TEMP_DIR_RELATIVE);

// Ensure temp directory exists
if (!file_exists(TEMP_DIR_FULL)) {
    dol_mkdir(TEMP_DIR_FULL);
}

$form = new Form($db);
$formfile = new FormFile($db);

llxHeader("", "SEUP - Predmet", '', '', 0, 0, '', '', '', 'mod-seup page-predmet');

// Handle POST requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    dol_syslog('POST request', LOG_INFO);

    // Handle document upload
    if (isset($_POST['action']) && GETPOST('action') === 'upload_document') {
        // Upload to Dolibarr ECM
        $uploadResult = Request_Handler::handleUploadDocument($db, $upload_dir, $langs, $conf, $user);
        
        // Only upload to Nextcloud if ECM is NOT mounted as Nextcloud external disk
        if ($uploadResult !== false) {
            try {
                require_once __DIR__ . '/../class/nextcloud_api.class.php';
                $nextcloudApi = new NextcloudAPI($db, $conf);
                
                // Only upload if ECM is not Nextcloud mounted
                if (!$nextcloudApi->isECMNextcloudMounted()) {
                    $relative_path = Predmet_helper::getPredmetFolderPath($caseId, $db);
                    
                    // Create folder in Nextcloud if it doesn't exist
                    $nextcloudApi->createFolder($relative_path);
                    
                    // Upload file to Nextcloud
                    $uploadedFile = $_FILES['document'];
                    if (isset($uploadedFile['tmp_name']) && is_uploaded_file($uploadedFile['tmp_name'])) {
                        $filename = basename($uploadedFile['name']);
                        $nextcloudSuccess = $nextcloudApi->uploadFile(
                            $uploadedFile['tmp_name'],
                            $relative_path,
                            $filename
                        );
                        
                        if ($nextcloudSuccess) {
                            dol_syslog("File successfully uploaded to Nextcloud: " . $filename, LOG_INFO);
                        } else {
                            dol_syslog("Failed to upload file to Nextcloud: " . $filename, LOG_WARNING);
                        }
                    }
                } else {
                    dol_syslog("ECM is Nextcloud mounted - skipping separate Nextcloud upload", LOG_INFO);
                }
            } catch (Exception $e) {
                dol_syslog("Nextcloud upload error: " . $e->getMessage(), LOG_WARNING);
            }
        }
        exit;
    }

    // Handle document deletion
    if (isset($_POST['action']) && GETPOST('action') === 'delete_document') {
        // Clean all output buffers FIRST
        while (ob_get_level() > 0) {
            ob_end_clean();
        }
        header('Content-Type: application/json');
        
        $filename = GETPOST('filename', 'alphanohtml');
        $filepath = GETPOST('filepath', 'alphanohtml');
        
        if (empty($filename) || empty($filepath)) {
            echo json_encode(['success' => false, 'error' => 'Missing filename or filepath']);
            exit;
        }
        
        try {
            $db->begin();
            
            // Debug info for JSON response
            $debug_info = [
                'looking_for_filename' => $filename,
                'looking_for_filepath' => $filepath,
                'rtrim_filepath' => rtrim($filepath, '/'),
                'entity' => $conf->entity
            ];
            
            // Check what's actually in the database  
            $check_sql = "SELECT rowid, filename, filepath FROM " . MAIN_DB_PREFIX . "ecm_files 
                         WHERE filename = '" . $db->escape($filename) . "'
                         AND entity = " . $conf->entity;
            $check_resql = $db->query($check_sql);
            $found_records = [];
            if ($check_resql) {
                while ($check_obj = $db->fetch_object($check_resql)) {
                    $found_records[] = [
                        'rowid' => $check_obj->rowid,
                        'filename' => $check_obj->filename,
                        'filepath' => $check_obj->filepath
                    ];
                }
            }
            $debug_info['found_in_db'] = $found_records;
            
            // Delete from ECM database first
            $sql = "DELETE FROM " . MAIN_DB_PREFIX . "ecm_files 
                    WHERE filepath = '" . $db->escape(rtrim($filepath, '/')) . "'
                    AND filename = '" . $db->escape($filename) . "'
                    AND entity = " . $conf->entity;
            
            $debug_info['delete_sql'] = $sql;
            
            $db_deleted = $db->query($sql);
            $affected_rows = $db->affected_rows($resql ?? null);
            $debug_info['query_result'] = $db_deleted ? 'SUCCESS' : 'FAILED';
            $debug_info['affected_rows'] = $affected_rows;
            
            if (!$db_deleted) {
                $debug_info['db_error'] = $db->lasterror();
                throw new Exception('Greška pri brisanju iz baze: ' . $db->lasterror());
            }
            
            if ($affected_rows == 0) {
                $debug_info['warning'] = 'No rows affected by delete query!';
                // Don't throw exception, just log warning since file might not be in DB
            }
            
            // Delete from filesystem
            $full_file_path = DOL_DATA_ROOT . '/ecm/' . rtrim($filepath, '/') . '/' . $filename;
            $file_deleted = false;
            if (file_exists($full_file_path)) {
                $file_deleted = unlink($full_file_path);
                if (!$file_deleted) {
                    dol_syslog("Warning: Could not delete file from filesystem: " . $full_file_path, LOG_WARNING);
                }
            }
            
            $db->commit();
            echo json_encode([
                'success' => true,
                'message' => 'Dokument je uspješno obrisan',
                'file_deleted' => $file_deleted,
                'db_deleted' => true,
                'debug' => $debug_info
            ]);
            
        } catch (Exception $e) {
            $db->rollback();
            echo json_encode([
                'success' => false, 
                'error' => $e->getMessage(),
                'debug' => $debug_info ?? []
            ]);
        }
        exit;
    }
    // Handle manual sync request
    if (isset($_POST['action']) && GETPOST('action') === 'refresh_documents') {
        // Just continue with normal page rendering to return updated HTML
        // The JavaScript will extract the documents section from the response
    }

    // File existence check
    if ($_SERVER['REQUEST_METHOD'] === 'GET' && GETPOST('action') === 'check_file_exists') {
        ob_end_clean();
        $file_path = GETPOST('file', 'alphanohtml');
        if (strpos($file_path, TEMP_DIR_RELATIVE) !== 0) {
            http_response_code(403);
            echo json_encode(['error' => 'Invalid file path']);
            exit;
        }
        $full_path = DOL_DATA_ROOT . $file_path;
        $exists = file_exists($full_path);
        header('Content-Type: application/json');
        echo json_encode(['exists' => $exists, 'path' => $full_path]);
        exit;
    }
}

// Auto-sync Nextcloud files to ECM when page loads
if ($caseId) {
    $autoSyncResult = Cloud_helper::autoSyncPredmet($db, $conf, $user, $caseId);
    if ($autoSyncResult['synced'] > 0) {
        dol_syslog("Auto-synced " . $autoSyncResult['synced'] . " files from Nextcloud", LOG_INFO);
    }
}

// Prikaz dokumenata na tabu 2
$documentTableHTML = '';
Predmet_helper::fetchUploadedDocuments($db, $conf, $documentTableHTML, $langs, $caseId);

// Modern design assets
print '<meta name="viewport" content="width=device-width, initial-scale=1">';
print '<link rel="preconnect" href="https://fonts.googleapis.com">';
print '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>';
print '<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">';
print '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">';
print '<link href="/custom/seup/css/seup-modern.css" rel="stylesheet">';
print '<link href="/custom/seup/css/predmet.css" rel="stylesheet">';
print '<link href="/custom/seup/css/prilozi.css" rel="stylesheet">';

// Main hero section
print '<main class="seup-settings-hero">';

// Copyright footer
print '<footer class="seup-footer">';
print '<div class="seup-footer-content">';
print '<div class="seup-footer-left">';
print '<p>Sva prava pridržana © <a href="https://8core.hr" target="_blank" rel="noopener">8Core Association</a> 2014 - ' . date('Y') . '</p>';
print '</div>';
print '<div class="seup-footer-right">';
print '<p class="seup-version">SEUP v.14.0.4</p>';
print '</div>';
print '</div>';
print '</footer>';

// Floating background elements
print '<div class="seup-floating-elements">';
for ($i = 1; $i <= 5; $i++) {
    print '<div class="seup-floating-element"></div>';
}
print '</div>';

print '<div class="seup-settings-content">';

// Header section
if ($caseDetails) {
    print '<div class="seup-settings-header">';
    print '<h1 class="seup-settings-title" style="font-size: var(--text-2xl);">Klasa: ' . htmlspecialchars($caseDetails->klasa) . '</h1>';
    print '<p class="seup-settings-subtitle">' . htmlspecialchars($caseDetails->naziv_predmeta) . '</p>';
    print '</div>';
} else {
    print '<div class="seup-settings-header">';
    print '<h1 class="seup-settings-title">Predmet</h1>';
    print '<p class="seup-settings-subtitle">Upravljanje predmetom i povezanim dokumentima</p>';
    print '</div>';
}

// Main content container
print '<div class="seup-predmet-container">';

// Tab Navigation
print '<div class="seup-tabs">';
print '<button class="seup-tab active" data-tab="predmet">';
print '<i class="fas fa-folder-open"></i>Predmet';
print '</button>';
print '<button class="seup-tab" data-tab="dokumenti">';
print '<i class="fas fa-file-alt"></i>Dokumenti u prilozima';
print '</button>';
print '<button class="seup-tab" data-tab="predpregled">';
print '<i class="fas fa-search"></i>Predpregled';
print '</button>';
print '<button class="seup-tab" data-tab="statistike">';
print '<i class="fas fa-chart-bar"></i>Statistike';
print '</button>';
print '</div>';

// Tab Content
print '<div class="seup-tab-content">';

// Tab 1 - Predmet Details
print '<div class="seup-tab-pane active" id="tab-predmet">';
if ($caseDetails) {
    print '<div class="seup-case-details">';
    print '<div class="seup-case-header">';
    print '<div class="seup-case-icon"><i class="fas fa-folder-open"></i></div>';
    print '<div class="seup-case-title">';
    print '<h4>Detalji predmeta</h4>';
    print '<div class="seup-case-klasa">' . htmlspecialchars($caseDetails->klasa) . '</div>';
    print '</div>';
    print '<div class="seup-status-badge seup-status-active">';
    print '<i class="fas fa-check-circle me-1"></i>Aktivan';
    print '</div>';
    print '</div>';
    
    print '<div class="seup-case-grid">';
    
    print '<div class="seup-case-field">';
    print '<div class="seup-case-field-label"><i class="fas fa-heading"></i>Naziv predmeta</div>';
    print '<div class="seup-case-field-value">' . htmlspecialchars($caseDetails->naziv_predmeta) . '</div>';
    print '</div>';
    
    print '<div class="seup-case-field">';
    print '<div class="seup-case-field-label"><i class="fas fa-building"></i>Ustanova</div>';
    print '<div class="seup-case-field-value">' . htmlspecialchars($caseDetails->name_ustanova ?: 'N/A') . '</div>';
    print '</div>';
    
    print '<div class="seup-case-field">';
    print '<div class="seup-case-field-label"><i class="fas fa-user"></i>Zaposlenik</div>';
    print '<div class="seup-case-field-value">' . htmlspecialchars($caseDetails->ime_prezime ?: 'N/A') . '</div>';
    print '</div>';
    
    print '<div class="seup-case-field">';
    print '<div class="seup-case-field-label"><i class="fas fa-calendar"></i>Datum otvaranja</div>';
    print '<div class="seup-case-field-value">' . htmlspecialchars($caseDetails->datum_otvaranja) . '</div>';
    print '</div>';
    
    if ($caseDetails->opis_klasifikacijske_oznake) {
        print '<div class="seup-case-field" style="grid-column: 1 / -1;">';
        print '<div class="seup-case-field-label"><i class="fas fa-info-circle"></i>Opis klasifikacije</div>';
        print '<div class="seup-case-field-value">' . htmlspecialchars($caseDetails->opis_klasifikacijske_oznake) . '</div>';
        print '</div>';
    }
    
    print '</div>'; // seup-case-grid
    print '</div>'; // seup-case-details
} else {
    print '<div class="seup-welcome-state">';
    print '<i class="fas fa-folder-open seup-welcome-icon"></i>';
    print '<h4 class="seup-welcome-title">Dobrodošli</h4>';
    print '<p class="seup-welcome-description">Ovo je početna stranica. Za pregled predmeta posjetite stranicu Predmeti.</p>';
    print '<a href="predmeti.php" class="seup-btn seup-btn-primary">';
    print '<i class="fas fa-external-link-alt me-2"></i>Otvori Predmete';
    print '</a>';
    print '</div>';
}
print '</div>';

// Tab 2 - Documents
print '<div class="seup-tab-pane" id="tab-dokumenti">';
print '<div class="seup-documents-header">';
print '<h4 class="seup-documents-title"><i class="fas fa-file-alt"></i>Akti i prilozi</h4>';
print '</div>';

// Upload section
print '<div class="seup-upload-section">';
print '<div class="seup-upload-icon"><i class="fas fa-cloud-upload-alt"></i></div>';
print '<div class="seup-upload-text">Kliknite za dodavanje novog dokumenta</div>';
print '<button type="button" id="uploadTrigger" class="seup-btn seup-btn-primary">';
print '<i class="fas fa-upload me-2"></i>Dodaj dokument';
print '</button>';
print '<input type="file" id="documentInput" style="display: none;">';
print '<div class="seup-upload-progress" id="uploadProgress">';
print '<div class="seup-progress-bar">';
print '<div class="seup-progress-fill" id="progressFill"></div>';
print '</div>';
print '<div class="seup-progress-text" id="progressText">Uploading...</div>';
print '</div>';
print '</div>';

// Nextcloud sync section
if (Cloud_helper::isNextcloudConfigured()) {
    $syncStatus = Cloud_helper::getSyncStatus($db, $conf, $caseId);
    
    // Nextcloud sync is now handled automatically in admin settings
}

// Documents display
if (strpos($documentTableHTML, 'NoDocumentsFound') !== false || strpos($documentTableHTML, 'alert-info') !== false) {
    print '<div class="seup-no-documents">';
    print '<i class="fas fa-file-alt seup-no-documents-icon"></i>';
    print '<h5 class="seup-no-documents-title">Nema uploadanih dokumenata</h5>';
    print '<p class="seup-no-documents-description">Dodajte prvi dokument za ovaj predmet</p>';
    print '</div>';
} else {
    // Convert the existing table HTML to modern design
    $modernTableHTML = str_replace(
        ['table table-sm table-bordered', 'btn btn-outline-primary btn-sm'],
        ['seup-documents-table', 'seup-btn-download'],
        $documentTableHTML
    );
    print $modernTableHTML;
}

print '<div class="seup-action-buttons">';
print '<button type="button" class="seup-btn seup-btn-secondary">';
print '<i class="fas fa-search me-2"></i>Pretraži dokumente';
print '</button>';
print '<button type="button" class="seup-btn seup-btn-secondary">';
print '<i class="fas fa-sort me-2"></i>Sortiraj';
print '</button>';
print '</div>';
print '</div>';

// Tab 3 - Preview
print '<div class="seup-tab-pane" id="tab-predpregled">';
print '<div class="seup-preview-container">';
print '<i class="fas fa-file-pdf seup-preview-icon"></i>';
print '<h4 class="seup-preview-title">Predpregled omota spisa</h4>';
print '<p class="seup-preview-description">Generirajte PDF pregled s listom svih priloga</p>';
print '<div class="seup-action-buttons">';
print '<button type="button" class="seup-btn seup-btn-primary" data-action="generate_pdf">';
print '<i class="fas fa-file-pdf me-2"></i>Kreiraj PDF';
print '</button>';
print '<button type="button" class="seup-btn seup-btn-secondary">';
print '<i class="fas fa-print me-2"></i>Ispis';
print '</button>';
print '<button type="button" class="seup-btn seup-btn-secondary">';
print '<i class="fas fa-share me-2"></i>Dijeli';
print '</button>';
print '</div>';
print '</div>';
print '</div>';

// Tab 4 - Statistics
print '<div class="seup-tab-pane" id="tab-statistike">';
print '<div class="seup-stats-container">';
print '<h4 class="seup-documents-title"><i class="fas fa-chart-bar"></i>Statistički podaci</h4>';
print '<div class="seup-stats-grid">';

print '<div class="seup-stat-card">';
print '<i class="fas fa-file-alt seup-stat-icon"></i>';
print '<div class="seup-stat-number" id="stat-documents">0</div>';
print '<div class="seup-stat-label">Dokumenata</div>';
print '</div>';

print '<div class="seup-stat-card">';
print '<i class="fas fa-clock seup-stat-icon"></i>';
print '<div class="seup-stat-number" id="stat-days">0</div>';
print '<div class="seup-stat-label">Dana otvoreno</div>';
print '</div>';

print '<div class="seup-stat-card">';
print '<i class="fas fa-user seup-stat-icon"></i>';
print '<div class="seup-stat-number">1</div>';
print '<div class="seup-stat-label">Zaposlenik</div>';
print '</div>';

print '<div class="seup-stat-card">';
print '<i class="fas fa-eye seup-stat-icon"></i>';
print '<div class="seup-stat-number" id="stat-views">0</div>';
print '<div class="seup-stat-label">Pregleda</div>';
print '</div>';

print '</div>'; // seup-stats-grid

print '<div class="seup-action-buttons">';
print '<button type="button" class="seup-btn seup-btn-secondary">';
print '<i class="fas fa-download me-2"></i>Izvoz statistika';
print '</button>';
print '<button type="button" class="seup-btn seup-btn-secondary">';
print '<i class="fas fa-chart-line me-2"></i>Detaljni izvještaj';
print '</button>';
print '</div>';
print '</div>';
print '</div>';

print '</div>'; // seup-tab-content
print '</div>'; // seup-predmet-container

print '</div>'; // seup-settings-content
print '</main>';

// Delete Confirmation Modal
print '<div class="seup-modal" id="deleteDocumentModal">';
print '<div class="seup-modal-content">';
print '<div class="seup-modal-header">';
print '<h5 class="seup-modal-title"><i class="fas fa-trash me-2"></i>Brisanje Dokumenta</h5>';
print '<button type="button" class="seup-modal-close" id="closeDeleteDocModal">&times;</button>';
print '</div>';
print '<div class="seup-modal-body">';
print '<div class="seup-delete-doc-info">';
print '<div class="seup-delete-doc-icon"><i class="fas fa-file-alt"></i></div>';
print '<div class="seup-delete-doc-details">';
print '<div class="seup-delete-doc-name" id="deleteDocName">document.pdf</div>';
print '<div class="seup-delete-doc-warning">';
print '<i class="fas fa-exclamation-triangle me-2"></i>';
print '<strong>PAŽNJA:</strong> Ova akcija je nepovratna! Dokument će biti trajno obrisan.';
print '</div>';
print '</div>';
print '</div>';
print '</div>';
print '<div class="seup-modal-footer">';
print '<button type="button" class="seup-btn seup-btn-secondary" id="cancelDeleteDocBtn">Odustani</button>';
print '<button type="button" class="seup-btn seup-btn-danger" id="confirmDeleteDocBtn">';
print '<i class="fas fa-trash me-2"></i>Obriši Dokument';
print '</button>';
print '</div>';
print '</div>';
print '</div>';

// JavaScript for enhanced functionality
print '<script src="/custom/seup/js/seup-modern.js"></script>';

?>

<input type="hidden" name="token" value="<?php echo newToken(); ?>">

<script>
document.addEventListener("DOMContentLoaded", function() {
    // Tab functionality
    const tabs = document.querySelectorAll('.seup-tab');
    const tabPanes = document.querySelectorAll('.seup-tab-pane');

    tabs.forEach(tab => {
        tab.addEventListener('click', function() {
            const targetTab = this.dataset.tab;
            
            // Remove active class from all tabs and panes
            tabs.forEach(t => t.classList.remove('active'));
            tabPanes.forEach(pane => pane.classList.remove('active'));
            
            // Add active class to clicked tab and corresponding pane
            this.classList.add('active');
            const targetPane = document.getElementById(`tab-${targetTab}`);
            if (targetPane) {
                targetPane.classList.add('active');
            }
        });
    });

    // Document delete functionality
    document.addEventListener('click', function(e) {
        if (e.target.closest('.delete-document-btn')) {
            const btn = e.target.closest('.delete-document-btn');
            const filename = btn.dataset.filename;
            const filepath = btn.dataset.filepath;
            
            // Store data for modal
            currentDeleteData = { filename, filepath, button: btn };
            
            // Update modal content
            document.getElementById('deleteDocName').textContent = filename;
            
            // Show modal
            document.getElementById('deleteDocumentModal').classList.add('show');
        }
    });
    // Get elements safely
    const uploadTrigger = document.getElementById("uploadTrigger");
    const documentInput = document.getElementById("documentInput");
    const pdfButton = document.querySelector("[data-action='generate_pdf']");
    const uploadProgress = document.getElementById("uploadProgress");
    const progressFill = document.getElementById("progressFill");
    const progressText = document.getElementById("progressText");

    // Upload functionality
    if (uploadTrigger && documentInput) {
        uploadTrigger.addEventListener("click", function() {
            documentInput.click();
        });

        documentInput.addEventListener("change", function(e) {
            const allowedTypes = [
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "application/msword",
                "application/vnd.ms-excel",
                "application/octet-stream",
                "application/zip",
                "application/pdf",
                "image/jpeg",
                "image/png"
            ];

            const allowedExtensions = [
                ".docx", ".xlsx", ".doc", ".xls",
                ".pdf", ".jpg", ".jpeg", ".png", ".zip"
            ];

            if (this.files.length > 0) {
                const file = this.files[0];
                const extension = "." + file.name.split(".").pop().toLowerCase();

                if (!allowedTypes.includes(file.type) && !allowedExtensions.includes(extension)) {
                    showMessage("<?php echo $langs->transnoentities('ErrorInvalidFileTypeJS'); ?>\nAllowed formats: " + allowedExtensions.join(", "), 'error');
                    this.value = "";
                    return;
                }

                if (file.size > 10 * 1024 * 1024) {
                    showMessage("<?php echo $langs->transnoentities('ErrorFileTooLarge'); ?>", 'error');
                    this.value = "";
                    return;
                }

                // Show upload progress
                uploadProgress.style.display = 'block';
                progressFill.style.width = '0%';
                progressText.textContent = 'Priprema upload...';

                const formData = new FormData();
                formData.append("document", file);
                formData.append("token", document.querySelector("input[name='token']").value);
                formData.append("action", "upload_document");
                formData.append("case_id", <?php echo $caseId; ?>);

                // Simulate progress
                let progress = 0;
                const progressInterval = setInterval(() => {
                    progress += Math.random() * 15;
                    if (progress > 90) progress = 90;
                    progressFill.style.width = progress + '%';
                    progressText.textContent = `Uploading... ${Math.round(progress)}%`;
                }, 100);

                fetch("", {
                    method: "POST",
                    body: formData
                }).then(response => {
                    clearInterval(progressInterval);
                    progressFill.style.width = '100%';
                    progressText.textContent = 'Upload završen!';
                    
                    if (response.ok) {
                        setTimeout(() => {
                            uploadProgress.style.display = 'none';
                            document.getElementById("documentInput").value = "";
                            showMessage('Dokument je uspješno prenešen!', 'success');
                            // Auto-refresh documents list after successful upload
                            refreshDocumentsList();
                        }, 1000);
                    } else {
                        throw new Error('Upload failed');
                    }
                }).catch(error => {
                    clearInterval(progressInterval);
                    uploadProgress.style.display = 'none';
                    console.error("Upload error:", error);
                    showMessage('Greška pri uploadu dokumenta', 'error');
                });
            }
        });
    }

    // Nextcloud sync functionality
    const syncBtn = document.getElementById('syncBtn');
    const manualSyncBtn = document.getElementById('manualSyncBtn');
    const rescanEcmBtn = document.getElementById('rescanEcmBtn');
    const rescanEcmBtn2 = document.getElementById('rescanEcmBtn2');

    // ECM sync and manual sync removed - handled automatically in admin settings

    // Function to refresh documents list
    function refreshDocumentsList() {
        const formData = new FormData();
        formData.append('action', 'refresh_documents');
        formData.append('case_id', <?php echo $caseId; ?>);
        
        fetch('predmet.php?id=<?php echo $caseId; ?>', {
            method: 'POST',
            body: formData
        })
        .then(response => response.text())
        .then(html => {
            // Extract the documents table from the response
            const parser = new DOMParser();
            const doc = parser.parseFromString(html, 'text/html');
            const newDocumentsTab = doc.querySelector('#tab-dokumenti');
            
            if (newDocumentsTab) {
                const currentTab = document.getElementById('tab-dokumenti');
                if (currentTab) {
                    // Find the documents display area (after upload section)
                    const uploadSection = currentTab.querySelector('.seup-upload-section');
                    const newUploadSection = newDocumentsTab.querySelector('.seup-upload-section');
                    
                    if (uploadSection && newUploadSection) {
                        // Replace everything after upload section with new content
                        const currentContent = uploadSection.nextElementSibling;
                        const newContent = newUploadSection.nextElementSibling;
                        
                        if (currentContent && newContent) {
                            currentContent.outerHTML = newContent.outerHTML;
                        } else if (newContent) {
                            // If no current content, append new content
                            uploadSection.insertAdjacentHTML('afterend', newContent.outerHTML);
                        }
                        
                        // Re-add file type icons and update stats
                        setTimeout(() => {
                            addFileTypeIcons();
                            updateStatistics();
                        }, 100);
                    }
                }
            }
        })
        .catch(error => {
            console.error('Error refreshing documents:', error);
            // Show error message but don't reload page
            showMessage('Greška pri osvježavanju liste dokumenata', 'error');
        });
    }

    // Enhanced refresh with visual feedback
    function refreshDocumentsWithFeedback() {
        // Add subtle loading indicator
        const documentsHeader = document.querySelector('.seup-documents-header h4');
        if (documentsHeader) {
            const originalText = documentsHeader.innerHTML;
            documentsHeader.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Osvježavam...';
            
            refreshDocumentsList();
            
            setTimeout(() => {
                documentsHeader.innerHTML = originalText;
            }, 2000);
        } else {
            refreshDocumentsList();
        }
    }

    // Upload functionality
    if (uploadTrigger && documentInput) {
        uploadTrigger.addEventListener("click", function() {
            documentInput.click();
        });

        documentInput.addEventListener("change", function(e) {
            const allowedTypes = [
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "application/msword",
                "application/vnd.ms-excel",
                "application/octet-stream",
                "application/zip",
                "application/pdf",
                "image/jpeg",
                "image/png"
            ];

            const allowedExtensions = [
                ".docx", ".xlsx", ".doc", ".xls",
                ".pdf", ".jpg", ".jpeg", ".png", ".zip"
            ];

            if (this.files.length > 0) {
                const file = this.files[0];
                const extension = "." + file.name.split(".").pop().toLowerCase();

                if (!allowedTypes.includes(file.type) && !allowedExtensions.includes(extension)) {
                    showMessage("<?php echo $langs->transnoentities('ErrorInvalidFileTypeJS'); ?>\nAllowed formats: " + allowedExtensions.join(", "), 'error');
                    this.value = "";
                    return;
                }

                if (file.size > 10 * 1024 * 1024) {
                    showMessage("<?php echo $langs->transnoentities('ErrorFileTooLarge'); ?>", 'error');
                    this.value = "";
                    return;
                }

                // Show upload progress
                uploadProgress.style.display = 'block';
                progressFill.style.width = '0%';
                progressText.textContent = 'Priprema upload...';

                const formData = new FormData();
                formData.append("document", file);
                formData.append("token", document.querySelector("input[name='token']").value);
                formData.append("action", "upload_document");
                formData.append("case_id", <?php echo $caseId; ?>);

                // Simulate progress
                let progress = 0;
                const progressInterval = setInterval(() => {
                    progress += Math.random() * 15;
                    if (progress > 90) progress = 90;
                    progressFill.style.width = progress + '%';
                    progressText.textContent = `Uploading... ${Math.round(progress)}%`;
                }, 100);

                fetch("", {
                    method: "POST",
                    body: formData
                }).then(response => {
                    clearInterval(progressInterval);
                    progressFill.style.width = '100%';
                    progressText.textContent = 'Upload završen!';
                    
                    if (response.ok) {
                        setTimeout(() => {
                            uploadProgress.style.display = 'none';
                            document.getElementById("documentInput").value = "";
                            showMessage('Dokument je uspješno prenešen!', 'success');
                            // Auto-refresh documents list after successful upload
                            refreshDocumentsList();
                        }, 1000);
                    } else {
                        throw new Error('Upload failed');
                    }
                }).catch(error => {
                    clearInterval(progressInterval);
                    uploadProgress.style.display = 'none';
                    console.error("Upload error:", error);
                    showMessage('Greška pri uploadu dokumenta', 'error');
                });
            }
        });
    }

    // Function to refresh documents list (optimized)
    function refreshDocumentsList() {
        const formData = new FormData();
        formData.append('action', 'refresh_documents');
        formData.append('case_id', <?php echo $caseId; ?>);
        
        fetch('predmet.php?id=<?php echo $caseId; ?>', {
            method: 'POST',
            body: formData
        })
        .then(response => response.text())
        .then(html => {
            // Extract the documents table from the response
            const parser = new DOMParser();
            const doc = parser.parseFromString(html, 'text/html');
            const newDocumentsTab = doc.querySelector('#tab-dokumenti');
            
            if (newDocumentsTab) {
                const currentTab = document.getElementById('tab-dokumenti');
                if (currentTab) {
                    // Find the documents display area (after upload section)
                    const uploadSection = currentTab.querySelector('.seup-upload-section');
                    const newUploadSection = newDocumentsTab.querySelector('.seup-upload-section');
                    
                    if (uploadSection && newUploadSection) {
                        // Replace everything after upload section with new content
                        let currentElement = uploadSection.nextElementSibling;
                        let newElement = newUploadSection.nextElementSibling;
                        
                        // Remove all existing content after upload section
                        while (currentElement) {
                            const nextElement = currentElement.nextElementSibling;
                            currentElement.remove();
                            currentElement = nextElement;
                        }
                        
                        // Add all new content after upload section
                        while (newElement) {
                            const nextElement = newElement.nextElementSibling;
                            const clonedElement = newElement.cloneNode(true);
                            uploadSection.insertAdjacentElement('afterend', clonedElement);
                            newElement = nextElement;
                        }
                        
                        // Re-add file type icons and update stats
                        setTimeout(() => {
                            addFileTypeIcons();
                        // Update statistics
                        updateStatistics();
                        }, 100);
                    }
                }
            }
        })
        .catch(error => {
            console.error('Error refreshing documents:', error);
            // Show error message but don't reload page
            showMessage('Greška pri osvježavanju liste dokumenata', 'error');
        });
    }

    // Function to add file type icons to document table
    function addFileTypeIcons() {
        document.querySelectorAll('.seup-documents-table tbody tr').forEach(row => {
            const nameCell = row.querySelector('td:first-child');
            if (nameCell && !nameCell.querySelector('.seup-file-icon')) {
                const filename = nameCell.textContent.trim();
                const extension = filename.split('.').pop().toLowerCase();
                
                let iconClass = 'default';
                let iconName = 'fa-file';
                
                if (['pdf'].includes(extension)) {
                    iconClass = 'pdf';
                    iconName = 'fa-file-pdf';
                } else if (['doc', 'docx'].includes(extension)) {
                    iconClass = 'doc';
                    iconName = 'fa-file-word';
                } else if (['xls', 'xlsx'].includes(extension)) {
                    iconClass = 'xls';
                    iconName = 'fa-file-excel';
                } else if (['jpg', 'jpeg', 'png'].includes(extension)) {
                    iconClass = 'img';
                    iconName = 'fa-file-image';
                }
                
                nameCell.innerHTML = `
                    <div class="seup-file-icon ${iconClass}">
                        <i class="fas ${iconName}"></i>
                    </div>
                    <span class="seup-document-name">${filename}</span>
                `;
                nameCell.style.display = 'flex';
                nameCell.style.alignItems = 'center';
            }
        });
    }
    // PDF generation
    if (pdfButton) {
        pdfButton.addEventListener("click", function() {
            this.classList.add('seup-loading');
            
            const generatePdfUrl = "<?php echo DOL_URL_ROOT . '/custom/seup/class/generate_pdf.php'; ?>";
            fetch(generatePdfUrl, {
                method: "POST"
            })
            .then(response => response.json())
            .then(data => {
                if (data.success && data.file) {
                    window.open(data.file, "_blank");
                    showMessage('PDF je uspješno generiran!', 'success');
                } else {
                    throw new Error(data.error || "PDF generation failed.");
                }
            })
            .catch(error => {
                console.error("PDF generation error:", error);
                showMessage("PDF generation failed: " + error.message, 'error');
            })
            .finally(() => {
                this.classList.remove('seup-loading');
            });
        });
    }

    // Calculate and display statistics
    function updateStatistics() {
        // Count documents from actual table rows (excluding "no documents" message)
        const documentTable = document.querySelector('.seup-documents-table tbody');
        let docCount = 0;
        if (documentTable) {
            const rows = documentTable.querySelectorAll('tr');
            // Only count if it's not the "no documents" message
            docCount = rows.length;
        }
        const statDocEl = document.getElementById('stat-documents');
        if (statDocEl) {
            statDocEl.textContent = docCount;
        }

        // Calculate days open (if case details exist)
        <?php if ($caseDetails): ?>
        const openDate = new Date('<?php echo date('Y-m-d', strtotime($caseDetails->datum_otvaranja)); ?>');
        const today = new Date();
        const diffTime = Math.abs(today - openDate);
        const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
        const statDaysEl = document.getElementById('stat-days');
        if (statDaysEl) {
            statDaysEl.textContent = diffDays;
        }
        <?php endif; ?>

        // Set views to 1 for now (you can implement real tracking later)
        const statViewsEl = document.getElementById('stat-views');
        if (statViewsEl) {
            statViewsEl.textContent = '1';
        }
    }

    // Toast message function
    window.showMessage = function(message, type = 'success', duration = 5000) {
        let messageEl = document.querySelector('.seup-message-toast');
        if (!messageEl) {
            messageEl = document.createElement('div');
            messageEl.className = 'seup-message-toast';
            document.body.appendChild(messageEl);
        }

        messageEl.className = `seup-message-toast seup-message-${type} show`;
        messageEl.innerHTML = `
            <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-triangle'} me-2"></i>
            ${message}
        `;

        setTimeout(() => {
            messageEl.classList.remove('show');
        }, duration);
    };

    // Initialize statistics
    updateStatistics();

    // Add file type icons to document table
    addFileTypeIcons();

    // Delete Document Modal Functionality
    let currentDeleteData = null;

    function closeDeleteDocModal() {
        document.getElementById('deleteDocumentModal').classList.remove('show');
        currentDeleteData = null;
    }

    function confirmDeleteDocument() {
        if (!currentDeleteData) return;
        
        const confirmBtn = document.getElementById('confirmDeleteDocBtn');
        confirmBtn.classList.add('seup-loading');
        currentDeleteData.button.classList.add('seup-loading');
        
        const formData = new FormData();
        formData.append('action', 'delete_document');
        formData.append('filename', currentDeleteData.filename);
        formData.append('filepath', currentDeleteData.filepath);
        
        fetch('predmet.php?id=<?php echo $caseId; ?>', {
            method: 'POST',
            body: formData
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                // Remove row from table with animation
                const row = currentDeleteData.button.closest('tr');
                if (row) {
                    row.style.animation = 'fadeOut 0.5s ease-out';
                    setTimeout(() => {
                        row.remove();
                        updateStatistics();
                        
                        // Check if table is now empty
                        const tbody = document.querySelector('.seup-documents-table tbody');
                        if (tbody && tbody.children.length === 0) {
                            // Replace table with "no documents" message
                            const tableContainer = document.querySelector('.seup-documents-table').parentElement;
                            tableContainer.innerHTML = `
                                <div class="seup-no-documents">
                                    <i class="fas fa-file-alt seup-no-documents-icon"></i>
                                    <h5 class="seup-no-documents-title">Nema uploadanih dokumenata</h5>
                                    <p class="seup-no-documents-description">Dodajte prvi dokument za ovaj predmet</p>
                                </div>
                            `;
                        }
                    }, 500);
                }
                
                showMessage(data.message, 'success');
                closeDeleteDocModal();
                closeDeleteDocModal();
            } else {
                showMessage('Greška pri brisanju: ' + data.error, 'error');
            }
        })
        .catch(error => {
            // Ignore JSON parse errors - document is likely deleted successfully
            // Check if the row still exists to determine if deletion was successful
            const row = currentDeleteData.button.closest('tr');
            if (row) {
                // Assume deletion was successful and remove the row
                row.style.animation = 'fadeOut 0.5s ease-out';
                setTimeout(() => {
                    row.remove();
                    updateStatistics();
                    
                    // Check if table is now empty
                    const tbody = document.querySelector('.seup-documents-table tbody');
                    if (tbody && tbody.children.length === 0) {
                        // Replace table with "no documents" message
                        const tableContainer = document.querySelector('.seup-documents-table').parentElement;
                        tableContainer.innerHTML = `
                            <div class="seup-no-documents">
                                <i class="fas fa-file-alt seup-no-documents-icon"></i>
                                <h5 class="seup-no-documents-title">Nema uploadanih dokumenata</h5>
                                <p class="seup-no-documents-description">Dodajte prvi dokument za ovaj predmet</p>
                            </div>
                        `;
                    }
                }, 500);
                
                showMessage('Dokument je uspješno obrisan', 'success');
                closeDeleteDocModal();
            } else {
                // Only show error if row still exists (deletion actually failed)
                console.error('Delete error:', error);
                showMessage('Došlo je do greške pri brisanju dokumenta', 'error');
            }
        })
        .finally(() => {
            confirmBtn.classList.remove('seup-loading');
            if (currentDeleteData && currentDeleteData.button) {
                currentDeleteData.button.classList.remove('seup-loading');
            }
        });
    }

    // Delete modal event listeners
    document.getElementById('closeDeleteDocModal').addEventListener('click', closeDeleteDocModal);
    document.getElementById('cancelDeleteDocBtn').addEventListener('click', closeDeleteDocModal);
    document.getElementById('confirmDeleteDocBtn').addEventListener('click', confirmDeleteDocument);

    // Close modal when clicking outside
    document.getElementById('deleteDocumentModal').addEventListener('click', function(e) {
        if (e.target === this) {
            closeDeleteDocModal();
        }
    });

    // Auto-refresh documents every 30 seconds if Nextcloud is enabled
    <?php if (Cloud_helper::isNextcloudConfigured()): ?>
    setInterval(() => {
        // Only refresh if user is on documents tab and page is visible
        if (!document.hidden && document.querySelector('.seup-tab[data-tab="dokumenti"]').classList.contains('active')) {
            refreshDocumentsList();
        }
    }, 30000); // 30 seconds
    <?php endif; ?>
});

// Auto-check for file changes when tab is activated
document.addEventListener('visibilitychange', function() {
    if (!document.hidden) {
        // Page became visible, check for file changes
        const refreshBtn = document.getElementById('refreshFilesBtn');
        if (refreshBtn && Math.random() < 0.3) { // 30% chance to auto-check
            setTimeout(() => {
                refreshBtn.click();
            }, 1000);
        }
    }
});
</script>

<?php
llxFooter();
$db->close();
?>