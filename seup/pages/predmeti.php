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
 *	\file       seup/predmeti.php
 *	\ingroup    seup
 *	\brief      List of open cases
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
require_once __DIR__ . '/../class/request_handler.class.php';

// Ensure database tables exist (including a_arhiva)
Predmet_helper::createSeupDatabaseTables($db);

// Load translation files
$langs->loadLangs(array("seup@seup"));

// Security check
$socid = GETPOST('socid', 'int');
if (isset($user->socid) && $user->socid > 0) {
    $action = '';
    $socid = $user->socid;
}

// Fetch sorting parameters
$sortField = GETPOST('sort', 'aZ09') ?: 'ID_predmeta';
$sortOrder = GETPOST('order', 'aZ09') ?: 'ASC';

// Validate sort fields
$allowedSortFields = ['ID_predmeta', 'klasa_br', 'naziv_predmeta', 'name_ustanova', 'ime_prezime', 'tstamp_created'];
if (!in_array($sortField, $allowedSortFields)) {
    $sortField = 'ID_predmeta';
}
$sortOrder = ($sortOrder === 'ASC') ? 'ASC' : 'DESC';

// Handle POST requests for archiving
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = GETPOST('action', 'alpha');
    
    if ($action === 'archive_predmet') {
        header('Content-Type: application/json');
        ob_end_clean();
        
        $predmet_id = GETPOST('predmet_id', 'int');
        $razlog = GETPOST('razlog', 'alphanohtml');
        
        if (!$predmet_id) {
            echo json_encode(['success' => false, 'error' => 'Missing predmet ID']);
            exit;
        }
        
        $result = Predmet_helper::archivePredmet($db, $conf, $user, $predmet_id, $razlog);
        echo json_encode($result);
        exit;
    }
}

// Use helper to build ORDER BY
$orderByClause = Predmet_helper::buildOrderByKlasa($sortField, $sortOrder);

// Fetch all open cases with proper sorting
$sql = "SELECT 
            p.ID_predmeta,
            p.klasa_br,
            p.sadrzaj,
            p.dosje_broj,
            p.godina,
            p.predmet_rbr,
            p.naziv_predmeta,
            DATE_FORMAT(p.tstamp_created, '%d/%m/%Y') as datum_otvaranja,
            u.name_ustanova,
            k.ime_prezime,
            ko.opis_klasifikacijske_oznake
        FROM " . MAIN_DB_PREFIX . "a_predmet p
        LEFT JOIN " . MAIN_DB_PREFIX . "a_oznaka_ustanove u ON p.ID_ustanove = u.ID_ustanove
        LEFT JOIN " . MAIN_DB_PREFIX . "a_interna_oznaka_korisnika k ON p.ID_interna_oznaka_korisnika = k.ID
        LEFT JOIN " . MAIN_DB_PREFIX . "a_klasifikacijska_oznaka ko ON p.ID_klasifikacijske_oznake = ko.ID_klasifikacijske_oznake
        WHERE p.ID_predmeta NOT IN (
            SELECT ID_predmeta FROM " . MAIN_DB_PREFIX . "a_arhiva WHERE status_arhive = 'active'
        )
        {$orderByClause}";

$resql = $db->query($sql);
$predmeti = [];
if ($resql) {
    while ($obj = $db->fetch_object($resql)) {
        $predmeti[] = $obj;
    }
}

$form = new Form($db);
llxHeader("", $langs->trans("OpenCases"), '', '', 0, 0, '', '', '', 'mod-seup page-predmeti');

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
print '<h1 class="seup-settings-title">Otvoreni Predmeti</h1>';
print '<p class="seup-settings-subtitle">Pregled i upravljanje svim aktivnim predmetima u sustavu</p>';
print '</div>';

// Main content card
print '<div class="seup-predmeti-container">';
print '<div class="seup-settings-card seup-card-wide animate-fade-in-up">';
print '<div class="seup-card-header">';
print '<div class="seup-card-icon"><i class="fas fa-folder-open"></i></div>';
print '<div class="seup-card-header-content">';
print '<h3 class="seup-card-title">Aktivni Predmeti</h3>';
print '<p class="seup-card-description">Pregled svih otvorenih predmeta s mogućnostima sortiranja i pretraživanja</p>';
print '</div>';
print '<div class="seup-card-actions">';
print '<button type="button" class="seup-btn seup-btn-primary" id="noviPredmetBtn">';
print '<i class="fas fa-plus me-2"></i>Novi Predmet';
print '</button>';
print '</div>';
print '</div>';

// Search and filter section
print '<div class="seup-table-controls">';
print '<div class="seup-search-container">';
print '<div class="seup-search-input-wrapper">';
print '<i class="fas fa-search seup-search-icon"></i>';
print '<input type="text" id="searchInput" class="seup-search-input" placeholder="Pretraži predmete...">';
print '</div>';
print '</div>';
print '<div class="seup-filter-controls">';
print '<select id="filterUstanova" class="seup-filter-select">';
print '<option value="">Sve ustanove</option>';
// Add unique ustanove from predmeti
$ustanove = array_unique(array_filter(array_column($predmeti, 'name_ustanova')));
foreach ($ustanove as $ustanova) {
    print '<option value="' . htmlspecialchars($ustanova) . '">' . htmlspecialchars($ustanova) . '</option>';
}
print '</select>';
print '<select id="filterZaposlenik" class="seup-filter-select">';
print '<option value="">Svi zaposlenici</option>';
// Add unique zaposlenici from predmeti
$zaposlenici = array_unique(array_filter(array_column($predmeti, 'ime_prezime')));
foreach ($zaposlenici as $zaposlenik) {
    print '<option value="' . htmlspecialchars($zaposlenik) . '">' . htmlspecialchars($zaposlenik) . '</option>';
}
print '</select>';
print '<select id="filterGodina" class="seup-filter-select">';
print '<option value="">Sve godine</option>';
// Add unique godine from predmeti
$godine = array_unique(array_filter(array_column($predmeti, 'godina')));
sort($godine);
foreach ($godine as $godina) {
    print '<option value="' . htmlspecialchars($godina) . '">20' . htmlspecialchars($godina) . '</option>';
}
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
print sortableHeader('ID_predmeta', 'ID', $sortField, $sortOrder, 'fas fa-hashtag');
print sortableHeader('klasa_br', 'Klasa', $sortField, $sortOrder, 'fas fa-layer-group');
print sortableHeader('naziv_predmeta', 'Naziv Predmeta', $sortField, $sortOrder, 'fas fa-heading');
print sortableHeader('name_ustanova', 'Ustanova', $sortField, $sortOrder, 'fas fa-building');
print sortableHeader('ime_prezime', 'Zaposlenik', $sortField, $sortOrder, 'fas fa-user');
print sortableHeader('tstamp_created', 'Datum Otvaranja', $sortField, $sortOrder, 'fas fa-calendar');
print '<th class="seup-table-th"><i class="fas fa-cogs me-2"></i>Akcije</th>';
print '</tr>';
print '</thead>';
print '<tbody class="seup-table-body">';

if (count($predmeti)) {
    foreach ($predmeti as $index => $predmet) {
        $klasa = $predmet->klasa_br . '-' . $predmet->sadrzaj . '/' .
            $predmet->godina . '-' . $predmet->dosje_broj . '/' .
            $predmet->predmet_rbr;
        
        $rowClass = ($index % 2 === 0) ? 'seup-table-row-even' : 'seup-table-row-odd';
        print '<tr class="seup-table-row ' . $rowClass . '" data-id="' . $predmet->ID_predmeta . '">';
        
        print '<td class="seup-table-td">';
        print '<span class="seup-badge seup-badge-neutral">' . $predmet->ID_predmeta . '</span>';
        print '</td>';
        
        // Make Klasa badge clickable
        $url = dol_buildpath('/custom/seup/pages/predmet.php', 1) . '?id=' . $predmet->ID_predmeta;
        print '<td class="seup-table-td">';
        print '<a href="' . $url . '" class="seup-badge seup-badge-primary seup-klasa-link">' . $klasa . '</a>';
        print '</td>';
        
        print '<td class="seup-table-td">';
        print '<div class="seup-naziv-cell" title="' . htmlspecialchars($predmet->naziv_predmeta) . '">';
        print dol_trunc($predmet->naziv_predmeta, 50);
        print '</div>';
        print '</td>';
        
        print '<td class="seup-table-td">';
        print '<span class="seup-ustanova-badge">' . ($predmet->name_ustanova ?: 'N/A') . '</span>';
        print '</td>';
        
        print '<td class="seup-table-td">';
        print '<div class="seup-user-info">';
        print '<i class="fas fa-user-circle me-2"></i>';
        print $predmet->ime_prezime ?: 'N/A';
        print '</div>';
        print '</td>';
        
        print '<td class="seup-table-td">';
        print '<div class="seup-date-info">';
        print '<i class="fas fa-calendar me-2"></i>';
        print $predmet->datum_otvaranja;
        print '</div>';
        print '</td>';

        // Action buttons
        print '<td class="seup-table-td">';
        print '<div class="seup-action-buttons">';
        print '<a href="' . $url . '" class="seup-action-btn seup-btn-view" title="Pregled detalja">';
        print '<i class="fas fa-eye"></i>';
        print '</a>';
        print '<button class="seup-action-btn seup-btn-edit" title="Uredi" data-id="' . $predmet->ID_predmeta . '">';
        print '<i class="fas fa-edit"></i>';
        print '</button>';
        print '<button class="seup-action-btn seup-btn-archive" title="Arhiviraj" data-id="' . $predmet->ID_predmeta . '">';
        print '<i class="fas fa-archive"></i>';
        print '</button>';
        print '</div>';
        print '</td>';

        print '</tr>';
    }
} else {
    print '<tr class="seup-table-row">';
    print '<td colspan="7" class="seup-table-empty">';
    print '<div class="seup-empty-state">';
    print '<i class="fas fa-folder-open seup-empty-icon"></i>';
    print '<h4 class="seup-empty-title">Nema otvorenih predmeta</h4>';
    print '<p class="seup-empty-description">Kreirajte novi predmet za početak rada</p>';
    print '<button type="button" class="seup-btn seup-btn-primary mt-3" id="noviPredmetBtn2">';
    print '<i class="fas fa-plus me-2"></i>Kreiraj prvi predmet';
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
print '<span>Prikazano <strong id="visibleCount">' . count($predmeti) . '</strong> od <strong>' . count($predmeti) . '</strong> predmeta</span>';
print '</div>';
print '<div class="seup-table-actions">';
print '<button type="button" class="seup-btn seup-btn-secondary seup-btn-sm" id="exportBtn">';
print '<i class="fas fa-download me-2"></i>Izvoz Excel';
print '</button>';
print '<button type="button" class="seup-btn seup-btn-secondary seup-btn-sm" id="printBtn">';
print '<i class="fas fa-print me-2"></i>Ispis';
print '</button>';
print '</div>';
print '</div>';

print '</div>'; // seup-settings-card
print '</div>'; // seup-predmeti-container

print '</div>'; // seup-settings-content
print '</main>';

// Archive Modal
print '<div class="seup-modal" id="archiveModal">';
print '<div class="seup-modal-content">';
print '<div class="seup-modal-header">';
print '<h5 class="seup-modal-title"><i class="fas fa-archive me-2"></i>Arhiviranje Predmeta</h5>';
print '<button type="button" class="seup-modal-close" id="closeArchiveModal">&times;</button>';
print '</div>';
print '<div class="seup-modal-body">';
print '<div class="seup-archive-info">';
print '<div class="seup-archive-klasa" id="archiveKlasa">001-01/25-01/1</div>';
print '<div class="seup-archive-naziv" id="archiveNaziv">Naziv predmeta</div>';
print '<div class="seup-archive-warning">';
print '<i class="fas fa-exclamation-triangle me-2"></i>';
print 'Predmet će biti premješten u arhivu. Svi dokumenti će biti premješteni u arhivsku mapu.';
print '</div>';
print '</div>';
print '<div class="seup-form-group">';
print '<label for="archiveRazlog" class="seup-label">Razlog arhiviranja (opcionalno)</label>';
print '<textarea id="archiveRazlog" class="seup-textarea" rows="3" placeholder="Unesite razlog arhiviranja..."></textarea>';
print '</div>';
print '</div>';
print '<div class="seup-modal-footer">';
print '<button type="button" class="seup-btn seup-btn-secondary" id="cancelArchiveBtn">Odustani</button>';
print '<button type="button" class="seup-btn seup-btn-danger" id="confirmArchiveBtn">';
print '<i class="fas fa-archive me-2"></i>Arhiviraj';
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
    const noviPredmetBtn = document.getElementById("noviPredmetBtn");
    const noviPredmetBtn2 = document.getElementById("noviPredmetBtn2");
    
    if (noviPredmetBtn) {
        noviPredmetBtn.addEventListener("click", function() {
            this.classList.add('seup-loading');
            window.location.href = "novi_predmet.php";
        });
    }
    
    if (noviPredmetBtn2) {
        noviPredmetBtn2.addEventListener("click", function() {
            this.classList.add('seup-loading');
            window.location.href = "novi_predmet.php";
        });
    }

    // Enhanced search and filter functionality
    const searchInput = document.getElementById('searchInput');
    const filterUstanova = document.getElementById('filterUstanova');
    const filterZaposlenik = document.getElementById('filterZaposlenik');
    const filterGodina = document.getElementById('filterGodina');
    const tableRows = document.querySelectorAll('.seup-table-row[data-id]');
    const visibleCountSpan = document.getElementById('visibleCount');

    function filterTable() {
        const searchTerm = searchInput.value.toLowerCase();
        const selectedUstanova = filterUstanova.value;
        const selectedZaposlenik = filterZaposlenik.value;
        const selectedGodina = filterGodina.value;
        let visibleCount = 0;

        tableRows.forEach(row => {
            const cells = row.querySelectorAll('.seup-table-td');
            const rowText = Array.from(cells).map(cell => cell.textContent.toLowerCase()).join(' ');
            
            // Check search term
            const matchesSearch = !searchTerm || rowText.includes(searchTerm);
            
            // Check ustanova filter
            let matchesUstanova = true;
            if (selectedUstanova) {
                const ustanovaCell = cells[3]; // ustanova column
                matchesUstanova = ustanovaCell.textContent.trim() === selectedUstanova;
            }

            // Check zaposlenik filter
            let matchesZaposlenik = true;
            if (selectedZaposlenik) {
                const zaposlenikCell = cells[4]; // zaposlenik column
                matchesZaposlenik = zaposlenikCell.textContent.trim() === selectedZaposlenik;
            }

            // Check godina filter
            let matchesGodina = true;
            if (selectedGodina) {
                const klasaCell = cells[1]; // klasa column contains year
                const klasaText = klasaCell.textContent;
                // Extract year from klasa format: XXX-XX/YY-XX/X
                const yearMatch = klasaText.match(/\/(\d{2})-/);
                if (yearMatch) {
                    matchesGodina = yearMatch[1] === selectedGodina;
                }
            }

            if (matchesSearch && matchesUstanova && matchesZaposlenik && matchesGodina) {
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
    
    if (filterUstanova) {
        filterUstanova.addEventListener('change', filterTable);
    }

    if (filterZaposlenik) {
        filterZaposlenik.addEventListener('change', filterTable);
    }
    
    if (filterGodina) {
        filterGodina.addEventListener('change', filterTable);
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
    document.querySelectorAll('.seup-btn-edit').forEach(btn => {
        btn.addEventListener('click', function() {
            const id = this.dataset.id;
            this.classList.add('seup-loading');
            // Navigate to edit page
            window.location.href = `predmet.php?id=${id}&action=edit`;
        });
    });

    document.querySelectorAll('.seup-btn-archive').forEach(btn => {
        btn.addEventListener('click', function() {
            const id = this.dataset.id;
            const row = this.closest('.seup-table-row');
            const klasaCell = row.querySelector('.seup-klasa-link');
            const nazivCell = row.querySelector('.seup-naziv-cell');
            
            const klasa = klasaCell ? klasaCell.textContent : 'N/A';
            const naziv = nazivCell ? nazivCell.getAttribute('title') || nazivCell.textContent : 'N/A';
            
            openArchiveModal(id, klasa, naziv);
        });
    });

    // Export and print handlers
    document.getElementById('exportBtn').addEventListener('click', function() {
        this.classList.add('seup-loading');
        // Implement export functionality
        setTimeout(() => {
            this.classList.remove('seup-loading');
            showMessage('Excel izvoz je pokrenut', 'success');
        }, 2000);
    });

    document.getElementById('printBtn').addEventListener('click', function() {
        window.print();
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

    // Archive Modal Functionality
    let currentArchiveId = null;

    function openArchiveModal(predmetId, klasa, naziv) {
        currentArchiveId = predmetId;
        
        // Update modal content
        document.getElementById('archiveKlasa').textContent = klasa;
        document.getElementById('archiveNaziv').textContent = naziv;
        
        // Show modal
        document.getElementById('archiveModal').classList.add('show');
    }

    function closeArchiveModal() {
        document.getElementById('archiveModal').classList.remove('show');
        document.getElementById('archiveRazlog').value = '';
        currentArchiveId = null;
    }

    function confirmArchive() {
        if (!currentArchiveId) return;
        
        const razlog = document.getElementById('archiveRazlog').value.trim();
        const confirmBtn = document.getElementById('confirmArchiveBtn');
        
        // Add loading state
        confirmBtn.classList.add('seup-loading');
        
        const formData = new FormData();
        formData.append('action', 'archive_predmet');
        formData.append('predmet_id', currentArchiveId);
        if (razlog) {
            formData.append('razlog', razlog);
        }
        
        fetch('predmeti.php', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Remove row from table with animation
                const row = document.querySelector(`[data-id="${currentArchiveId}"]`);
                if (row) {
                    row.style.animation = 'fadeOut 0.5s ease-out';
                    setTimeout(() => {
                        row.remove();
                        updateVisibleCount();
                    }, 500);
                }
                
                showMessage(`Predmet uspješno arhiviran! Premješteno ${data.files_moved} dokumenata.`, 'success');
                closeArchiveModal();
            } else {
                showMessage('Greška pri arhiviranju: ' + data.error, 'error');
            }
        })
        .catch(error => {
            console.error('Archive error:', error);
            showMessage('Došlo je do greške pri arhiviranju', 'error');
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

    // Archive modal event listeners
    document.getElementById('closeArchiveModal').addEventListener('click', closeArchiveModal);
    document.getElementById('cancelArchiveBtn').addEventListener('click', closeArchiveModal);
    document.getElementById('confirmArchiveBtn').addEventListener('click', confirmArchive);

    // Close modal when clicking outside
    document.getElementById('archiveModal').addEventListener('click', function(e) {
        if (e.target === this) {
            closeArchiveModal();
        }
    });
});
</script>

<style>
/* Predmeti page specific styles */
.seup-predmeti-container {
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
  min-width: 180px;
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
  background: linear-gradient(135deg, var(--primary-500), var(--primary-600));
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
  background: var(--primary-25);
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

.seup-badge-primary {
  background: var(--primary-100);
  color: var(--primary-800);
  transition: all var(--transition-fast);
}

.seup-badge-primary:hover {
  background: var(--primary-200);
  color: var(--primary-900);
  text-decoration: none;
  transform: scale(1.05);
}

.seup-badge-neutral {
  background: var(--neutral-100);
  color: var(--neutral-800);
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

.seup-ustanova-badge {
  display: inline-flex;
  align-items: center;
  padding: var(--space-1) var(--space-2);
  background: var(--secondary-100);
  color: var(--secondary-800);
  border-radius: var(--radius-md);
  font-size: var(--text-xs);
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

.seup-btn-edit {
  background: var(--secondary-100);
  color: var(--secondary-600);
}

.seup-btn-edit:hover {
  background: var(--secondary-200);
  color: var(--secondary-700);
  transform: scale(1.1);
}

.seup-btn-archive {
  background: var(--warning-100);
  color: var(--warning-600);
}

.seup-btn-archive:hover {
  background: var(--warning-200);
  color: var(--warning-700);
  transform: scale(1.1);
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
  --primary-25: #f8faff;
  --neutral-25: #fcfcfc;
}

/* Animation keyframes */
@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

/* Archive Modal Styles */
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
  background: linear-gradient(135deg, var(--warning-500), var(--warning-600));
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

.seup-archive-info {
  background: var(--warning-50);
  border: 1px solid var(--warning-200);
  border-radius: var(--radius-lg);
  padding: var(--space-4);
  margin-bottom: var(--space-4);
}

.seup-archive-klasa {
  font-family: var(--font-family-mono);
  font-size: var(--text-lg);
  font-weight: var(--font-bold);
  color: var(--warning-800);
  margin-bottom: var(--space-2);
}

.seup-archive-warning {
  font-size: var(--text-sm);
  color: var(--warning-700);
  display: flex;
  align-items: center;
}

.seup-archive-naziv {
  font-size: var(--text-base);
  color: var(--secondary-700);
  margin-bottom: var(--space-3);
  font-weight: var(--font-medium);
}

.seup-btn-danger {
  background: linear-gradient(135deg, var(--error-500), var(--error-600));
  color: white;
  box-shadow: var(--shadow-md);
}

.seup-btn-danger:hover {
  background: linear-gradient(135deg, var(--error-600), var(--error-700));
  transform: translateY(-2px);
  box-shadow: var(--shadow-lg);
  color: white;
  text-decoration: none;
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