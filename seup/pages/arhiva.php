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
 * U skladu sa Zakonom o autorskom pravu i srodnim pravima 
 * (NN 167/03, 79/07, 80/11, 125/17), a osobito člancima 32. (pravo na umnožavanje), 35. 
 * (pravo na preradu i distribuciju) i 76. (kaznene odredbe), 
 * svako neovlašteno umnožavanje ili prerada ovog softvera smatra se prekršajem. 
 * Prema Kaznenom zakonu (NN 125/11, 144/12, 56/15), članak 228., stavak 1., 
 * prekršitelj se može kazniti novčanom kaznom ili zatvorom do jedne godine, 
 * a sud može izreći i dodatne mjere oduzimanja protivpravne imovinske koristi.
 * Bilo kakve izmjene, prijevodi, integracije ili dijeljenje koda bez izričitog pismenog 
 * odobrenja autora smatraju se kršenjem ugovora i zakona te će se pravno sankcionirati. 
 * Za sva pitanja, zahtjeve za licenciranjem ili dodatne informacije obratite se na info@8core.hr.
 */
/**
 *	\file       seup/arhiva.php
 *	\ingroup    seup
 *	\brief      Archive page for archived predmeti
 */

// Učitaj Dolibarr okruženje
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
require_once DOL_DOCUMENT_ROOT . '/core/class/html.form.class.php';

// Local classes
require_once __DIR__ . '/../class/predmet_helper.class.php';

// Ensure database tables exist
Predmet_helper::createSeupDatabaseTables($db);

// Load translation files
$langs->loadLangs(array("seup@seup"));

// Security check
$socid = GETPOST('socid', 'int');
if (isset($user->socid) && $user->socid > 0) {
    $action = '';
    $socid = $user->socid;
}

// Handle POST requests for restore
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = GETPOST('action', 'alpha');
    
    if ($action === 'restore_predmet') {
        header('Content-Type: application/json');
        ob_end_clean();
        
        $arhiva_id = GETPOST('arhiva_id', 'int');
        
        if (!$arhiva_id) {
            echo json_encode(['success' => false, 'error' => 'Missing arhiva ID']);
            exit;
        }
        
        $result = Predmet_helper::restorePredmet($db, $conf, $user, $arhiva_id);
        echo json_encode($result);
        exit;
    }
    
    if ($action === 'delete_archive') {
        header('Content-Type: application/json');
        ob_end_clean();
        
        $arhiva_id = GETPOST('arhiva_id', 'int');
        
        if (!$arhiva_id) {
            echo json_encode(['success' => false, 'error' => 'Missing arhiva ID']);
            exit;
        }
        
        $result = Predmet_helper::deleteArchive($db, $conf, $user, $arhiva_id);
        echo json_encode($result);
        exit;
    }
}

// Fetch sorting parameters
$sortField = GETPOST('sort', 'aZ09') ?: 'datum_arhiviranja';
$sortOrder = GETPOST('order', 'aZ09') ?: 'DESC';

// Validate sort fields
$allowedSortFields = ['ID_arhive', 'klasa_predmeta', 'naziv_predmeta', 'broj_dokumenata', 'datum_arhiviranja'];
if (!in_array($sortField, $allowedSortFields)) {
    $sortField = 'datum_arhiviranja';
}
$sortOrder = ($sortOrder === 'ASC') ? 'ASC' : 'DESC';

// Fetch archived predmeti
$sql = "SELECT 
            a.ID_arhive,
            a.ID_predmeta,
            a.klasa_predmeta,
            a.naziv_predmeta,
            a.broj_dokumenata,
            a.razlog_arhiviranja,
            DATE_FORMAT(a.datum_arhiviranja, '%d.%m.%Y %H:%i') as datum_arhiviranja,
            CONCAT(u.firstname, ' ', u.lastname) as arhivirao_korisnik
        FROM " . MAIN_DB_PREFIX . "a_arhiva a
        LEFT JOIN " . MAIN_DB_PREFIX . "user u ON a.fk_user_arhivirao = u.rowid
        WHERE a.status_arhive = 'active'
        ORDER BY {$sortField} {$sortOrder}";

$resql = $db->query($sql);
$arhivirani = [];
if ($resql) {
    while ($obj = $db->fetch_object($resql)) {
        $arhivirani[] = $obj;
    }
}

$form = new Form($db);
llxHeader("", "Arhiva", '', '', 0, 0, '', '', '', 'mod-seup page-arhiva');

// Modern design assets
print '<meta name="viewport" content="width=device-width, initial-scale=1">';
print '<link rel="preconnect" href="https://fonts.googleapis.com">';
print '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>';
print '<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">';
print '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">';
print '<link href="/custom/seup/css/seup-modern.css" rel="stylesheet">';

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
print '<div class="seup-settings-header">';
print '<h1 class="seup-settings-title">Arhiva Predmeta</h1>';
print '<p class="seup-settings-subtitle">Pregled i upravljanje arhiviranim predmetima i dokumentima</p>';
print '</div>';

// Main content card
print '<div class="seup-arhiva-container">';
print '<div class="seup-settings-card seup-card-wide animate-fade-in-up">';
print '<div class="seup-card-header">';
print '<div class="seup-card-icon"><i class="fas fa-archive"></i></div>';
print '<div class="seup-card-header-content">';
print '<h3 class="seup-card-title">Arhivirani Predmeti</h3>';
print '<p class="seup-card-description">Pregled svih arhiviranih predmeta s mogućnostima pretraživanja i vraćanja</p>';
print '</div>';
print '<div class="seup-card-actions">';
print '<button type="button" class="seup-btn seup-btn-secondary" id="backToActiveBtn">';
print '<i class="fas fa-arrow-left me-2"></i>Aktivni Predmeti';
print '</button>';
print '</div>';
print '</div>';

// Search and filter section
print '<div class="seup-table-controls">';
print '<div class="seup-search-container">';
print '<div class="seup-search-input-wrapper">';
print '<i class="fas fa-search seup-search-icon"></i>';
print '<input type="text" id="searchInput" class="seup-search-input" placeholder="Pretraži arhivu...">';
print '</div>';
print '</div>';
print '<div class="seup-filter-controls">';
print '<select id="filterKlasa" class="seup-filter-select">';
print '<option value="">Sve klase</option>';
// Add unique klase from arhivirani
$klase = array_unique(array_filter(array_column($arhivirani, 'klasa_predmeta')));
sort($klase);
foreach ($klase as $klasa) {
    print '<option value="' . htmlspecialchars($klasa) . '">' . htmlspecialchars($klasa) . '</option>';
}
print '</select>';
print '<select id="filterDokumenti" class="seup-filter-select">';
print '<option value="">Svi dokumenti</option>';
print '<option value="0">Bez dokumenata</option>';
print '<option value="1-5">1-5 dokumenata</option>';
print '<option value="6-10">6-10 dokumenata</option>';
print '<option value="10+">10+ dokumenata</option>';
print '</select>';
print '<select id="filterDatum" class="seup-filter-select">';
print '<option value="">Svi datumi</option>';
print '<option value="today">Danas</option>';
print '<option value="week">Ovaj tjedan</option>';
print '<option value="month">Ovaj mjesec</option>';
print '<option value="year">Ova godina</option>';
print '</select>';
print '</div>';
print '</div>';

// Enhanced table with modern styling
print '<div class="seup-table-container">';
print '<table class="seup-table">';
print '<thead class="seup-table-header">';
print '<tr>';

// Function to generate sortable header
function sortableHeader($field, $label, $currentSort, $currentOrder, $icon = '')
{
    $newOrder = ($currentSort === $field && $currentOrder === 'DESC') ? 'ASC' : 'DESC';
    $sortIcon = '';

    if ($currentSort === $field) {
        $sortIcon = ($currentOrder === 'ASC')
            ? ' <i class="fas fa-arrow-up seup-sort-icon"></i>'
            : ' <i class="fas fa-arrow-down seup-sort-icon"></i>';
    }

    return '<th class="seup-table-th sortable-header">' .
        '<a href="?sort=' . $field . '&order=' . $newOrder . '" class="seup-sort-link">' .
        ($icon ? '<i class="' . $icon . ' me-2"></i>' : '') .
        $label . $sortIcon .
        '</a></th>';
}

// Generate sortable headers with icons
print sortableHeader('ID_arhive', 'ID', $sortField, $sortOrder, 'fas fa-hashtag');
print sortableHeader('klasa_predmeta', 'Klasa', $sortField, $sortOrder, 'fas fa-layer-group');
print sortableHeader('naziv_predmeta', 'Naziv Predmeta', $sortField, $sortOrder, 'fas fa-heading');
print sortableHeader('broj_dokumenata', 'Dokumenti', $sortField, $sortOrder, 'fas fa-file-alt');
print sortableHeader('datum_arhiviranja', 'Datum Arhiviranja', $sortField, $sortOrder, 'fas fa-calendar');
print '<th class="seup-table-th"><i class="fas fa-user me-2"></i>Arhivirao</th>';
print '<th class="seup-table-th"><i class="fas fa-cogs me-2"></i>Akcije</th>';
print '</tr>';
print '</thead>';
print '<tbody class="seup-table-body">';

if (count($arhivirani)) {
    foreach ($arhivirani as $index => $arhiva) {
        $rowClass = ($index % 2 === 0) ? 'seup-table-row-even' : 'seup-table-row-odd';
        print '<tr class="seup-table-row ' . $rowClass . '" data-id="' . $arhiva->ID_arhive . '" data-predmet-id="' . $arhiva->ID_predmeta . '">';
        
        print '<td class="seup-table-td">';
        print '<span class="seup-badge seup-badge-neutral">' . $arhiva->ID_arhive . '</span>';
        print '</td>';
        
        print '<td class="seup-table-td">';
        print '<span class="seup-badge seup-badge-archive seup-klasa-link">' . htmlspecialchars($arhiva->klasa_predmeta) . '</span>';
        print '</td>';
        
        print '<td class="seup-table-td">';
        print '<div class="seup-naziv-cell" title="' . htmlspecialchars($arhiva->naziv_predmeta) . '">';
        print dol_trunc($arhiva->naziv_predmeta, 50);
        print '</div>';
        print '</td>';
        
        print '<td class="seup-table-td">';
        if ($arhiva->broj_dokumenata > 0) {
            print '<span class="seup-badge seup-badge-success">';
            print '<i class="fas fa-file-alt me-1"></i>' . $arhiva->broj_dokumenata;
            print '</span>';
        } else {
            print '<span class="seup-badge seup-badge-neutral">';
            print '<i class="fas fa-file-alt me-1"></i>0';
            print '</span>';
        }
        print '</td>';
        
        print '<td class="seup-table-td">';
        print '<div class="seup-date-info">';
        print '<i class="fas fa-calendar me-2"></i>';
        print $arhiva->datum_arhiviranja;
        print '</div>';
        print '</td>';
        
        print '<td class="seup-table-td">';
        print '<div class="seup-user-info">';
        print '<i class="fas fa-user-circle me-2"></i>';
        print $arhiva->arhivirao_korisnik ?: 'N/A';
        print '</div>';
        print '</td>';

        // Action buttons
        print '<td class="seup-table-td">';
        print '<div class="seup-action-buttons">';
        print '<button class="seup-action-btn seup-btn-restore" title="Vrati u aktivne" data-id="' . $arhiva->ID_arhive . '">';
        print '<i class="fas fa-undo"></i>';
        print '</button>';
        print '<button class="seup-action-btn seup-btn-delete" title="Trajno obriši" data-id="' . $arhiva->ID_arhive . '">';
        print '<i class="fas fa-trash"></i>';
        print '</button>';
        print '</div>';
        print '</td>';

        print '</tr>';
    }
} else {
    print '<tr class="seup-table-row">';
    print '<td colspan="7" class="seup-table-empty">';
    print '<div class="seup-empty-state">';
    print '<i class="fas fa-archive seup-empty-icon"></i>';
    print '<h4 class="seup-empty-title">Nema arhiviranih predmeta</h4>';
    print '<p class="seup-empty-description">Arhivirani predmeti će se prikazati ovdje</p>';
    print '<button type="button" class="seup-btn seup-btn-primary mt-3" id="backToActiveBtn2">';
    print '<i class="fas fa-folder-open me-2"></i>Otvori Aktivne Predmete';
    print '</button>';
    print '</div>';
    print '</td>';
    print '</tr>';
}

print '</tbody>';
print '</table>';
print '</div>'; // seup-table-container

// Table footer with stats and actions
print '<div class="seup-table-footer">';
print '<div class="seup-table-stats">';
print '<i class="fas fa-info-circle me-2"></i>';
print '<span>Prikazano <strong id="visibleCount">' . count($arhivirani) . '</strong> od <strong>' . count($arhivirani) . '</strong> arhiviranih predmeta</span>';
print '</div>';
print '<div class="seup-table-actions">';
print '<button type="button" class="seup-btn seup-btn-secondary seup-btn-sm" id="exportBtn">';
print '<i class="fas fa-download me-2"></i>Izvoz Excel';
print '</button>';
print '<button type="button" class="seup-btn seup-btn-secondary seup-btn-sm" id="cleanupBtn">';
print '<i class="fas fa-broom me-2"></i>Čišćenje Arhive';
print '</button>';
print '</div>';
print '</div>';

print '</div>'; // seup-settings-card
print '</div>'; // seup-arhiva-container

print '</div>'; // seup-settings-content
print '</main>';

// Restore Modal
print '<div class="seup-modal" id="restoreModal">';
print '<div class="seup-modal-content">';
print '<div class="seup-modal-header">';
print '<h5 class="seup-modal-title"><i class="fas fa-undo me-2"></i>Vraćanje Predmeta</h5>';
print '<button type="button" class="seup-modal-close" id="closeRestoreModal">&times;</button>';
print '</div>';
print '<div class="seup-modal-body">';
print '<div class="seup-restore-info">';
print '<div class="seup-restore-klasa" id="restoreKlasa">001-01/25-01/1</div>';
print '<div class="seup-restore-naziv" id="restoreNaziv">Naziv predmeta</div>';
print '<div class="seup-restore-warning">';
print '<i class="fas fa-info-circle me-2"></i>';
print 'Predmet će biti vraćen u aktivne predmete. Svi dokumenti će biti premješteni natrag u radnu mapu.';
print '</div>';
print '</div>';
print '</div>';
print '<div class="seup-modal-footer">';
print '<button type="button" class="seup-btn seup-btn-secondary" id="cancelRestoreBtn">Odustani</button>';
print '<button type="button" class="seup-btn seup-btn-success" id="confirmRestoreBtn">';
print '<i class="fas fa-undo me-2"></i>Vrati';
print '</button>';
print '</div>';
print '</div>';
print '</div>';

// Delete Modal
print '<div class="seup-modal" id="deleteModal">';
print '<div class="seup-modal-content">';
print '<div class="seup-modal-header">';
print '<h5 class="seup-modal-title"><i class="fas fa-trash me-2"></i>Trajno Brisanje</h5>';
print '<button type="button" class="seup-modal-close" id="closeDeleteModal">&times;</button>';
print '</div>';
print '<div class="seup-modal-body">';
print '<div class="seup-delete-info">';
print '<div class="seup-delete-klasa" id="deleteKlasa">001-01/25-01/1</div>';
print '<div class="seup-delete-naziv" id="deleteNaziv">Naziv predmeta</div>';
print '<div class="seup-delete-warning">';
print '<i class="fas fa-exclamation-triangle me-2"></i>';
print '<strong>PAŽNJA:</strong> Ova akcija je nepovratna! Predmet i svi dokumenti će biti trajno obrisani.';
print '</div>';
print '</div>';
print '</div>';
print '<div class="seup-modal-footer">';
print '<button type="button" class="seup-btn seup-btn-secondary" id="cancelDeleteBtn">Odustani</button>';
print '<button type="button" class="seup-btn seup-btn-danger" id="confirmDeleteBtn">';
print '<i class="fas fa-trash me-2"></i>Trajno Obriši';
print '</button>';
print '</div>';
print '</div>';
print '</div>';

// JavaScript for enhanced functionality
print '<script src="/custom/seup/js/seup-modern.js"></script>';

?>

<script>
document.addEventListener("DOMContentLoaded", function() {
    // Navigation buttons
    const backToActiveBtn = document.getElementById("backToActiveBtn");
    const backToActiveBtn2 = document.getElementById("backToActiveBtn2");
    
    if (backToActiveBtn) {
        backToActiveBtn.addEventListener("click", function() {
            this.classList.add('seup-loading');
            window.location.href = "predmeti.php";
        });
    }
    
    if (backToActiveBtn2) {
        backToActiveBtn2.addEventListener("click", function() {
            this.classList.add('seup-loading');
            window.location.href = "predmeti.php";
        });
    }

    // Enhanced search and filter functionality
    const searchInput = document.getElementById('searchInput');
    const filterKlasa = document.getElementById('filterKlasa');
    const filterDokumenti = document.getElementById('filterDokumenti');
    const filterDatum = document.getElementById('filterDatum');
    const tableRows = document.querySelectorAll('.seup-table-row[data-id]');
    const visibleCountSpan = document.getElementById('visibleCount');

    function filterTable() {
        const searchTerm = searchInput.value.toLowerCase();
        const selectedKlasa = filterKlasa.value;
        const selectedDokumenti = filterDokumenti.value;
        const selectedDatum = filterDatum.value;
        let visibleCount = 0;

        tableRows.forEach(row => {
            const cells = row.querySelectorAll('.seup-table-td');
            const rowText = Array.from(cells).map(cell => cell.textContent.toLowerCase()).join(' ');
            
            // Check search term
            const matchesSearch = !searchTerm || rowText.includes(searchTerm);
            
            // Check klasa filter
            let matchesKlasa = true;
            if (selectedKlasa) {
                const klasaCell = cells[1]; // klasa column
                matchesKlasa = klasaCell.textContent.trim() === selectedKlasa;
            }

            // Check dokumenti filter
            let matchesDokumenti = true;
            if (selectedDokumenti) {
                const dokumentiCell = cells[3]; // broj_dokumenata column
                const brojDokumenata = parseInt(dokumentiCell.textContent.match(/\d+/)[0]);
                
                switch (selectedDokumenti) {
                    case '0':
                        matchesDokumenti = brojDokumenata === 0;
                        break;
                    case '1-5':
                        matchesDokumenti = brojDokumenata >= 1 && brojDokumenata <= 5;
                        break;
                    case '6-10':
                        matchesDokumenti = brojDokumenata >= 6 && brojDokumenata <= 10;
                        break;
                    case '10+':
                        matchesDokumenti = brojDokumenata > 10;
                        break;
                }
            }

            // Check datum filter
            let matchesDatum = true;
            if (selectedDatum) {
                const datumCell = cells[4]; // datum_arhiviranja column
                const datumText = datumCell.textContent;
                const today = new Date();
                
                // Parse date from DD.MM.YYYY HH:MM format
                const dateParts = datumText.match(/(\d{2})\.(\d{2})\.(\d{4})/);
                if (dateParts) {
                    const arhivaDate = new Date(dateParts[3], dateParts[2] - 1, dateParts[1]);
                    
                    switch (selectedDatum) {
                        case 'today':
                            matchesDatum = arhivaDate.toDateString() === today.toDateString();
                            break;
                        case 'week':
                            const weekAgo = new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000);
                            matchesDatum = arhivaDate >= weekAgo;
                            break;
                        case 'month':
                            const monthAgo = new Date(today.getFullYear(), today.getMonth() - 1, today.getDate());
                            matchesDatum = arhivaDate >= monthAgo;
                            break;
                        case 'year':
                            matchesDatum = arhivaDate.getFullYear() === today.getFullYear();
                            break;
                    }
                }
            }

            if (matchesSearch && matchesKlasa && matchesDokumenti && matchesDatum) {
                row.style.display = '';
                visibleCount++;
                // Add staggered animation
                row.style.animationDelay = `${visibleCount * 50}ms`;
                row.classList.add('animate-fade-in-up');
            } else {
                row.style.display = 'none';
                row.classList.remove('animate-fade-in-up');
            }
        });

        // Update visible count
        if (visibleCountSpan) {
            visibleCountSpan.textContent = visibleCount;
        }
    }

    if (searchInput) {
        searchInput.addEventListener('input', debounce(filterTable, 300));
    }
    
    if (filterKlasa) {
        filterKlasa.addEventListener('change', filterTable);
    }

    if (filterDokumenti) {
        filterDokumenti.addEventListener('change', filterTable);
    }
    
    if (filterDatum) {
        filterDatum.addEventListener('change', filterTable);
    }

    // Enhanced row interactions
    tableRows.forEach(row => {
        row.addEventListener('mouseenter', function() {
            this.style.transform = 'translateX(4px)';
        });
        
        row.addEventListener('mouseleave', function() {
            this.style.transform = 'translateX(0)';
        });
    });

    // Action button handlers
    document.querySelectorAll('.seup-btn-restore').forEach(btn => {
        btn.addEventListener('click', function() {
            const id = this.dataset.id;
            const row = this.closest('.seup-table-row');
            const klasaCell = row.querySelector('.seup-klasa-link');
            const nazivCell = row.querySelector('.seup-naziv-cell');
            
            const klasa = klasaCell ? klasaCell.textContent : 'N/A';
            const naziv = nazivCell ? nazivCell.getAttribute('title') || nazivCell.textContent : 'N/A';
            
            openRestoreModal(id, klasa, naziv);
        });
    });

    document.querySelectorAll('.seup-btn-delete').forEach(btn => {
        btn.addEventListener('click', function() {
            const id = this.dataset.id;
            const row = this.closest('.seup-table-row');
            const klasaCell = row.querySelector('.seup-klasa-link');
            const nazivCell = row.querySelector('.seup-naziv-cell');
            
            const klasa = klasaCell ? klasaCell.textContent : 'N/A';
            const naziv = nazivCell ? nazivCell.getAttribute('title') || nazivCell.textContent : 'N/A';
            
            openDeleteModal(id, klasa, naziv);
        });
    });

    // Export and cleanup handlers
    document.getElementById('exportBtn').addEventListener('click', function() {
        this.classList.add('seup-loading');
        // Implement export functionality
        setTimeout(() => {
            this.classList.remove('seup-loading');
            showMessage('Excel izvoz arhive je pokrenut', 'success');
        }, 2000);
    });

    document.getElementById('cleanupBtn').addEventListener('click', function() {
        if (confirm('Želite li pokrenuti čišćenje arhive? Ovo će obrisati stare arhivske zapise.')) {
            this.classList.add('seup-loading');
            // Implement cleanup functionality
            setTimeout(() => {
                this.classList.remove('seup-loading');
                showMessage('Čišćenje arhive je pokrenuto', 'success');
            }, 2000);
        }
    });

    // Modal functionality
    let currentRestoreId = null;
    let currentDeleteId = null;

    function openRestoreModal(arhivaId, klasa, naziv) {
        currentRestoreId = arhivaId;
        
        // Update modal content
        document.getElementById('restoreKlasa').textContent = klasa;
        document.getElementById('restoreNaziv').textContent = naziv;
        
        // Show modal
        document.getElementById('restoreModal').classList.add('show');
    }

    function closeRestoreModal() {
        document.getElementById('restoreModal').classList.remove('show');
        currentRestoreId = null;
    }

    function openDeleteModal(arhivaId, klasa, naziv) {
        currentDeleteId = arhivaId;
        
        // Update modal content
        document.getElementById('deleteKlasa').textContent = klasa;
        document.getElementById('deleteNaziv').textContent = naziv;
        
        // Show modal
        document.getElementById('deleteModal').classList.add('show');
    }

    function closeDeleteModal() {
        document.getElementById('deleteModal').classList.remove('show');
        currentDeleteId = null;
    }

    function confirmRestore() {
        if (!currentRestoreId) return;
        
        const confirmBtn = document.getElementById('confirmRestoreBtn');
        confirmBtn.classList.add('seup-loading');
        
        const formData = new FormData();
        formData.append('action', 'restore_predmet');
        formData.append('arhiva_id', currentRestoreId);
        
        fetch('arhiva.php', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Remove row from table with animation
                const row = document.querySelector(`[data-id="${currentRestoreId}"]`);
                if (row) {
                    row.style.animation = 'fadeOut 0.5s ease-out';
                    setTimeout(() => {
                        row.remove();
                        updateVisibleCount();
                    }, 500);
                }
                
                showMessage(`Predmet uspješno vraćen! Premješteno ${data.files_moved} dokumenata.`, 'success');
                closeRestoreModal();
            } else {
                showMessage('Greška pri vraćanju: ' + data.error, 'error');
            }
        })
        .catch(error => {
            console.error('Restore error:', error);
            showMessage('Došlo je do greške pri vraćanju', 'error');
        })
        .finally(() => {
            confirmBtn.classList.remove('seup-loading');
        });
    }

    function confirmDelete() {
        if (!currentDeleteId) return;
        
        const confirmBtn = document.getElementById('confirmDeleteBtn');
        confirmBtn.classList.add('seup-loading');
        
        const formData = new FormData();
        formData.append('action', 'delete_archive');
        formData.append('arhiva_id', currentDeleteId);
        
        fetch('arhiva.php', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Remove row from table with animation
                const row = document.querySelector(`[data-id="${currentDeleteId}"]`);
                if (row) {
                    row.style.animation = 'fadeOut 0.5s ease-out';
                    setTimeout(() => {
                        row.remove();
                        updateVisibleCount();
                    }, 500);
                }
                
                showMessage('Arhiva je trajno obrisana!', 'success');
                closeDeleteModal();
            } else {
                showMessage('Greška pri brisanju: ' + data.error, 'error');
            }
        })
        .catch(error => {
            console.error('Delete error:', error);
            showMessage('Došlo je do greške pri brisanju', 'error');
        })
        .finally(() => {
            confirmBtn.classList.remove('seup-loading');
        });
    }

    function updateVisibleCount() {
        const visibleRows = document.querySelectorAll('.seup-table-row[data-id]:not([style*="display: none"])');
        if (visibleCountSpan) {
            visibleCountSpan.textContent = visibleRows.length;
        }
    }

    // Modal event listeners
    document.getElementById('closeRestoreModal').addEventListener('click', closeRestoreModal);
    document.getElementById('cancelRestoreBtn').addEventListener('click', closeRestoreModal);
    document.getElementById('confirmRestoreBtn').addEventListener('click', confirmRestore);

    document.getElementById('closeDeleteModal').addEventListener('click', closeDeleteModal);
    document.getElementById('cancelDeleteBtn').addEventListener('click', closeDeleteModal);
    document.getElementById('confirmDeleteBtn').addEventListener('click', confirmDelete);

    // Close modals when clicking outside
    document.getElementById('restoreModal').addEventListener('click', function(e) {
        if (e.target === this) {
            closeRestoreModal();
        }
    });

    document.getElementById('deleteModal').addEventListener('click', function(e) {
        if (e.target === this) {
            closeDeleteModal();
        }
    });

    // Utility functions
    function debounce(func, wait) {
        let timeout;
        return function(...args) {
            clearTimeout(timeout);
            timeout = setTimeout(() => func.apply(this, args), wait);
        };
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

    // Initial staggered animation for existing rows
    tableRows.forEach((row, index) => {
        row.style.animationDelay = `${index * 100}ms`;
        row.classList.add('animate-fade-in-up');
    });
});
</script>

<style>
/* Archive page specific styles */
.seup-arhiva-container {
  max-width: 1400px;
  margin: 0 auto;
}

.seup-card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-4);
}

.seup-card-header-content {
  flex: 1;
}

.seup-card-actions {
  flex-shrink: 0;
}

/* Archive-specific badge */
.seup-badge-archive {
  background: var(--warning-100);
  color: var(--warning-800);
  font-family: var(--font-family-mono);
  font-weight: var(--font-semibold);
}

/* Restore Modal Styles */
.seup-restore-info {
  background: var(--success-50);
  border: 1px solid var(--success-200);
  border-radius: var(--radius-lg);
  padding: var(--space-4);
  margin-bottom: var(--space-4);
}

.seup-restore-klasa {
  font-family: var(--font-family-mono);
  font-size: var(--text-lg);
  font-weight: var(--font-bold);
  color: var(--success-800);
  margin-bottom: var(--space-2);
}

.seup-restore-naziv {
  font-size: var(--text-base);
  color: var(--secondary-700);
  margin-bottom: var(--space-3);
  font-weight: var(--font-medium);
}

.seup-restore-warning {
  font-size: var(--text-sm);
  color: var(--success-700);
  display: flex;
  align-items: center;
}

/* Delete Modal Styles */
.seup-delete-info {
  background: var(--error-50);
  border: 1px solid var(--error-200);
  border-radius: var(--radius-lg);
  padding: var(--space-4);
  margin-bottom: var(--space-4);
}

.seup-delete-klasa {
  font-family: var(--font-family-mono);
  font-size: var(--text-lg);
  font-weight: var(--font-bold);
  color: var(--error-800);
  margin-bottom: var(--space-2);
}

.seup-delete-naziv {
  font-size: var(--text-base);
  color: var(--secondary-700);
  margin-bottom: var(--space-3);
  font-weight: var(--font-medium);
}

.seup-delete-warning {
  font-size: var(--text-sm);
  color: var(--error-700);
  display: flex;
  align-items: flex-start;
  gap: var(--space-2);
}

/* Action buttons for archive */
.seup-btn-restore {
  background: var(--success-100);
  color: var(--success-600);
}

.seup-btn-restore:hover {
  background: var(--success-200);
  color: var(--success-700);
  transform: scale(1.1);
}

.seup-btn-delete {
  background: var(--error-100);
  color: var(--error-600);
}

.seup-btn-delete:hover {
  background: var(--error-200);
  color: var(--error-700);
  transform: scale(1.1);
}

/* Success button variant */
.seup-btn-success {
  background: linear-gradient(135deg, var(--success-500), var(--success-600));
  color: white;
  box-shadow: var(--shadow-md);
}

.seup-btn-success:hover {
  background: linear-gradient(135deg, var(--success-600), var(--success-700));
  transform: translateY(-2px);
  box-shadow: var(--shadow-lg);
  color: white;
  text-decoration: none;
}

/* Table Controls */
.seup-table-controls {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: var(--space-4);
  padding: var(--space-4) var(--space-6);
  background: var(--neutral-50);
  border-bottom: 1px solid var(--neutral-200);
}

.seup-search-container {
  flex: 1;
  max-width: 400px;
}

.seup-search-input-wrapper {
  position: relative;
}

.seup-search-icon {
  position: absolute;
  left: var(--space-3);
  top: 50%;
  transform: translateY(-50%);
  color: var(--secondary-400);
  font-size: var(--text-sm);
}

.seup-search-input {
  width: 100%;
  padding: var(--space-3) var(--space-3) var(--space-3) var(--space-10);
  border: 1px solid var(--neutral-300);
  border-radius: var(--radius-lg);
  font-size: var(--text-sm);
  transition: all var(--transition-fast);
  background: white;
}

.seup-search-input:focus {
  outline: none;
  border-color: var(--primary-500);
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
}

.seup-filter-controls {
  display: flex;
  gap: var(--space-3);
}

.seup-filter-select {
  padding: var(--space-2) var(--space-3);
  border: 1px solid var(--neutral-300);
  border-radius: var(--radius-lg);
  font-size: var(--text-sm);
  background: white;
  min-width: 160px;
}

/* Enhanced Table Styles */
.seup-table-container {
  background: white;
  border-radius: 0 0 var(--radius-2xl) var(--radius-2xl);
  overflow: hidden;
  box-shadow: var(--shadow-lg);
}

.seup-table {
  width: 100%;
  border-collapse: collapse;
  font-size: var(--text-sm);
}

.seup-table-header {
  background: linear-gradient(135deg, var(--warning-500), var(--warning-600));
  color: white;
}

.seup-table-th {
  padding: var(--space-4) var(--space-3);
  text-align: left;
  font-weight: var(--font-semibold);
  font-size: var(--text-xs);
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.seup-sort-link {
  color: white;
  text-decoration: none;
  display: flex;
  align-items: center;
  transition: opacity var(--transition-fast);
}

.seup-sort-link:hover {
  opacity: 0.8;
  color: white;
  text-decoration: none;
}

.seup-sort-icon {
  margin-left: var(--space-1);
  font-size: 10px;
}

.seup-table-body {
  background: white;
}

.seup-table-row {
  transition: all var(--transition-fast);
  border-bottom: 1px solid var(--neutral-100);
}

.seup-table-row:hover {
  background: var(--warning-25);
  transform: translateX(4px);
}

.seup-table-row-even {
  background: var(--neutral-25);
}

.seup-table-row-odd {
  background: white;
}

.seup-table-td {
  padding: var(--space-4) var(--space-3);
  vertical-align: middle;
}

/* Badge Styles */
.seup-badge {
  display: inline-flex;
  align-items: center;
  padding: var(--space-1) var(--space-2);
  border-radius: var(--radius-md);
  font-size: var(--text-xs);
  font-weight: var(--font-medium);
  line-height: 1;
  text-decoration: none;
}

.seup-badge-neutral {
  background: var(--neutral-100);
  color: var(--neutral-800);
}

.seup-badge-success {
  background: var(--success-100);
  color: var(--success-800);
}

.seup-klasa-link {
  font-family: var(--font-family-mono);
  font-weight: var(--font-semibold);
}

/* Cell Content Styles */
.seup-naziv-cell {
  max-width: 250px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  cursor: help;
  font-weight: var(--font-medium);
}

.seup-user-info,
.seup-date-info {
  display: flex;
  align-items: center;
  font-size: var(--text-sm);
  color: var(--secondary-700);
}

/* Action Buttons */
.seup-action-buttons {
  display: flex;
  gap: var(--space-2);
}

.seup-action-btn {
  width: 32px;
  height: 32px;
  border: none;
  border-radius: var(--radius-md);
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  transition: all var(--transition-fast);
  font-size: var(--text-xs);
  text-decoration: none;
}

.seup-btn-view {
  background: var(--primary-100);
  color: var(--primary-600);
}

.seup-btn-view:hover {
  background: var(--primary-200);
  color: var(--primary-700);
  transform: scale(1.1);
  text-decoration: none;
}

/* Empty State */
.seup-table-empty {
  padding: var(--space-12) var(--space-6);
  text-align: center;
}

.seup-empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--space-3);
}

.seup-empty-icon {
  font-size: 3rem;
  color: var(--secondary-300);
  margin-bottom: var(--space-2);
}

.seup-empty-title {
  font-size: var(--text-lg);
  font-weight: var(--font-semibold);
  color: var(--secondary-700);
  margin: 0;
}

.seup-empty-description {
  font-size: var(--text-sm);
  color: var(--secondary-500);
  margin: 0;
}

/* Table Footer */
.seup-table-footer {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--space-4) var(--space-6);
  background: var(--neutral-50);
  border-top: 1px solid var(--neutral-200);
}

.seup-table-stats {
  display: flex;
  align-items: center;
  font-size: var(--text-sm);
  color: var(--secondary-600);
}

.seup-table-actions {
  display: flex;
  gap: var(--space-2);
}

.seup-btn-sm {
  padding: var(--space-2) var(--space-3);
  font-size: var(--text-xs);
}

/* Loading state for action buttons */
.seup-action-btn.seup-loading {
  position: relative;
  color: transparent;
}

.seup-action-btn.seup-loading::after {
  content: '';
  position: absolute;
  top: 50%;
  left: 50%;
  width: 12px;
  height: 12px;
  margin: -6px 0 0 -6px;
  border: 2px solid transparent;
  border-top: 2px solid currentColor;
  border-radius: 50%;
  animation: spin 1s linear infinite;
}

/* Toast Messages */
.seup-message-toast {
  position: fixed;
  top: 20px;
  right: 20px;
  padding: var(--space-4) var(--space-6);
  border-radius: var(--radius-lg);
  color: white;
  font-weight: var(--font-medium);
  box-shadow: var(--shadow-xl);
  transform: translateX(400px);
  transition: transform var(--transition-normal);
  z-index: var(--z-tooltip);
  max-width: 400px;
}

.seup-message-toast.show {
  transform: translateX(0);
}

.seup-message-success {
  background: linear-gradient(135deg, var(--success-500), var(--success-600));
}

.seup-message-error {
  background: linear-gradient(135deg, var(--error-500), var(--error-600));
}

/* Modal Styles */
.seup-modal {
  display: none;
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(0, 0, 0, 0.5);
  backdrop-filter: blur(4px);
  z-index: var(--z-modal);
  align-items: center;
  justify-content: center;
}

.seup-modal.show {
  display: flex;
}

.seup-modal-content {
  background: white;
  border-radius: var(--radius-2xl);
  box-shadow: var(--shadow-2xl);
  max-width: 500px;
  width: 90%;
  max-height: 80vh;
  overflow: hidden;
  animation: modalSlideIn 0.3s ease-out;
}

.seup-modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--space-6);
  color: white;
}

.seup-modal-title {
  font-size: var(--text-lg);
  font-weight: var(--font-semibold);
  margin: 0;
}

.seup-modal-close {
  background: none;
  border: none;
  color: white;
  font-size: var(--text-lg);
  cursor: pointer;
  padding: var(--space-2);
  border-radius: var(--radius-md);
  transition: background var(--transition-fast);
}

.seup-modal-close:hover {
  background: rgba(255, 255, 255, 0.2);
}

.seup-modal-body {
  padding: var(--space-6);
}

.seup-modal-footer {
  display: flex;
  justify-content: flex-end;
  gap: var(--space-3);
  padding: var(--space-6);
  background: var(--neutral-50);
  border-top: 1px solid var(--neutral-200);
}

/* Restore modal header */
#restoreModal .seup-modal-header {
  background: linear-gradient(135deg, var(--success-500), var(--success-600));
}

/* Delete modal header */
#deleteModal .seup-modal-header {
  background: linear-gradient(135deg, var(--error-500), var(--error-600));
}

/* Responsive Design */
@media (max-width: 1024px) {
  .seup-table-controls {
    flex-direction: column;
    gap: var(--space-3);
  }
  
  .seup-search-container {
    max-width: none;
    width: 100%;
  }
  
  .seup-filter-controls {
    width: 100%;
    justify-content: flex-end;
  }
}

@media (max-width: 768px) {
  .seup-card-header {
    flex-direction: column;
    text-align: center;
  }
  
  .seup-table-footer {
    flex-direction: column;
    gap: var(--space-3);
    text-align: center;
  }
  
  .seup-table {
    font-size: var(--text-xs);
  }
  
  .seup-table-th,
  .seup-table-td {
    padding: var(--space-2);
  }
  
  .seup-naziv-cell {
    max-width: 120px;
  }
}

@media (max-width: 480px) {
  .seup-table-container {
    overflow-x: auto;
  }
  
  .seup-table {
    min-width: 800px;
  }
}

/* Additional color variants */
:root {
  --warning-25: #fffbeb;
  --neutral-25: #fcfcfc;
}

/* Animation keyframes */
@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

@keyframes modalSlideIn {
  from {
    opacity: 0;
    transform: scale(0.9) translateY(-20px);
  }
  to {
    opacity: 1;
    transform: scale(1) translateY(0);
  }
}

@keyframes fadeOut {
  from {
    opacity: 1;
    transform: translateX(0);
  }
  to {
    opacity: 0;
    transform: translateX(-100px);
  }
}
</style>

<?php
llxFooter();
$db->close();
?>