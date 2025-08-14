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
 *	\file       seup/klasifikacijske_oznake.php
 *	\ingroup    seup
 *	\brief      List of classification marks
 */

// Load Dolibarr environment
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

// Load translation files
$langs->loadLangs(array("seup@seup"));

// Security check
$socid = GETPOST('socid', 'int');
if (isset($user->socid) && $user->socid > 0) {
    $action = '';
    $socid = $user->socid;
}

// Fetch sorting parameters
$sortField = GETPOST('sort', 'aZ09') ?: 'ID_klasifikacijske_oznake';
$sortOrder = GETPOST('order', 'aZ09') ?: 'ASC';

// Validate sort fields
$allowedSortFields = [
    'ID_klasifikacijske_oznake',
    'klasa_broj',
    'sadrzaj',
    'dosje_broj',
    'vrijeme_cuvanja',
    'opis_klasifikacijske_oznake'
];

if (!in_array($sortField, $allowedSortFields)) {
    $sortField = 'ID_klasifikacijske_oznake';
}
$sortOrder = ($sortOrder === 'ASC') ? 'ASC' : 'DESC';

// Use specialized helper for classification marks
$orderByClause = Predmet_helper::buildKlasifikacijaOrderBy($sortField, $sortOrder, 'ko');

// Fetch all classification marks
$sql = "SELECT 
            ko.ID_klasifikacijske_oznake,
            ko.klasa_broj,
            ko.sadrzaj,
            ko.dosje_broj,
            ko.vrijeme_cuvanja,
            ko.opis_klasifikacijske_oznake
        FROM " . MAIN_DB_PREFIX . "a_klasifikacijska_oznaka ko
        {$orderByClause}";

$resql = $db->query($sql);
$oznake = [];
if ($resql) {
    while ($obj = $db->fetch_object($resql)) {
        $oznake[] = $obj;
    }
}

$form = new Form($db);
llxHeader("", $langs->trans("ClassificationMarks"), '', '', 0, 0, '', '', '', 'mod-seup page-oznake');

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
print '<h1 class="seup-settings-title">Plan Klasifikacijskih Oznaka</h1>';
print '<p class="seup-settings-subtitle">Pregled i upravljanje hijerarhijskim sustavom klasifikacije dokumenata i predmeta</p>';
print '</div>';

// Main content card
print '<div class="seup-classification-container">';
print '<div class="seup-settings-card seup-card-wide animate-fade-in-up">';
print '<div class="seup-card-header">';
print '<div class="seup-card-icon"><i class="fas fa-sitemap"></i></div>';
print '<div class="seup-card-header-content">';
print '<h3 class="seup-card-title">Klasifikacijske Oznake</h3>';
print '<p class="seup-card-description">Upravljanje hijerarhijskim sustavom klasifikacije dokumenata</p>';
print '</div>';
print '<div class="seup-card-actions">';
print '<button type="button" class="seup-btn seup-btn-primary" id="novaOznakaBtn">';
print '<i class="fas fa-plus me-2"></i>Nova Oznaka';
print '</button>';
print '</div>';
print '</div>';

// Search and filter section
print '<div class="seup-table-controls">';
print '<div class="seup-search-container">';
print '<div class="seup-search-input-wrapper">';
print '<i class="fas fa-search seup-search-icon"></i>';
print '<input type="text" id="searchInput" class="seup-search-input" placeholder="Pretraži oznake...">';
print '</div>';
print '</div>';
print '<div class="seup-filter-controls">';
print '<select id="filterVrijeme" class="seup-filter-select">';
print '<option value="">Sva vremena čuvanja</option>';
print '<option value="0">Trajno</option>';
for ($i = 1; $i <= 10; $i++) {
    print '<option value="' . $i . '">' . $i . ' godina</option>';
}
print '</select>';
print '<select id="filterKlasa" class="seup-filter-select">';
print '<option value="">Sve klase</option>';
// Add unique klase from oznake
$klase = array_unique(array_filter(array_column($oznake, 'klasa_broj')));
sort($klase);
foreach ($klase as $klasa) {
    print '<option value="' . htmlspecialchars($klasa) . '">' . htmlspecialchars($klasa) . '</option>';
}
print '</select>';
print '<select id="filterSadrzaj" class="seup-filter-select">';
print '<option value="">Svi sadržaji</option>';
// Add unique sadržaji from oznake
$sadrzaji = array_unique(array_filter(array_column($oznake, 'sadrzaj')));
sort($sadrzaji);
foreach ($sadrzaji as $sadrzaj) {
    print '<option value="' . htmlspecialchars($sadrzaj) . '">' . htmlspecialchars($sadrzaj) . '</option>';
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
print sortableHeader('ID_klasifikacijske_oznake', 'ID', $sortField, $sortOrder, 'fas fa-hashtag');
print sortableHeader('klasa_broj', 'Klasa', $sortField, $sortOrder, 'fas fa-layer-group');
print sortableHeader('sadrzaj', 'Sadržaj', $sortField, $sortOrder, 'fas fa-list');
print sortableHeader('dosje_broj', 'Dosje', $sortField, $sortOrder, 'fas fa-folder');
print sortableHeader('vrijeme_cuvanja', 'Čuvanje', $sortField, $sortOrder, 'fas fa-clock');
print sortableHeader('opis_klasifikacijske_oznake', 'Opis', $sortField, $sortOrder, 'fas fa-align-left');
print '<th class="seup-table-th"><i class="fas fa-cogs me-2"></i>Akcije</th>';
print '</tr>';
print '</thead>';
print '<tbody class="seup-table-body">';

if (count($oznake)) {
    foreach ($oznake as $index => $oznaka) {
        $rowClass = ($index % 2 === 0) ? 'seup-table-row-even' : 'seup-table-row-odd';
        print '<tr class="seup-table-row ' . $rowClass . '" data-id="' . $oznaka->ID_klasifikacijske_oznake . '">';
        
        print '<td class="seup-table-td">';
        print '<span class="seup-badge seup-badge-neutral">' . $oznaka->ID_klasifikacijske_oznake . '</span>';
        print '</td>';
        
        print '<td class="seup-table-td">';
        print '<span class="seup-badge seup-badge-primary">' . $oznaka->klasa_broj . '</span>';
        print '</td>';
        
        print '<td class="seup-table-td">';
        print '<span class="seup-badge seup-badge-secondary">' . $oznaka->sadrzaj . '</span>';
        print '</td>';
        
        print '<td class="seup-table-td">';
        print '<span class="seup-badge seup-badge-accent">' . $oznaka->dosje_broj . '</span>';
        print '</td>';

        // Handle retention period display
        print '<td class="seup-table-td">';
        if ($oznaka->vrijeme_cuvanja == 0) {
            print '<span class="seup-badge seup-badge-success"><i class="fas fa-infinity me-1"></i>Trajno</span>';
        } else {
            $yearsText = ($oznaka->vrijeme_cuvanja == 1) ? 'godina' : 'godina';
            print '<span class="seup-badge seup-badge-warning"><i class="fas fa-clock me-1"></i>' . $oznaka->vrijeme_cuvanja . ' ' . $yearsText . '</span>';
        }
        print '</td>';

        print '<td class="seup-table-td">';
        print '<div class="seup-description-cell" title="' . htmlspecialchars($oznaka->opis_klasifikacijske_oznake) . '">';
        print dol_trunc($oznaka->opis_klasifikacijske_oznake, 50);
        print '</div>';
        print '</td>';

        // Action buttons
        print '<td class="seup-table-td">';
        print '<div class="seup-action-buttons">';
        print '<button class="seup-action-btn seup-btn-edit" title="Uredi" data-id="' . $oznaka->ID_klasifikacijske_oznake . '">';
        print '<i class="fas fa-edit"></i>';
        print '</button>';
        print '<button class="seup-action-btn seup-btn-delete" title="Obriši" data-id="' . $oznaka->ID_klasifikacijske_oznake . '">';
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
    print '<i class="fas fa-sitemap seup-empty-icon"></i>';
    print '<h4 class="seup-empty-title">Nema klasifikacijskih oznaka</h4>';
    print '<p class="seup-empty-description">Dodajte novu klasifikacijsku oznaku za početak</p>';
    print '<button type="button" class="seup-btn seup-btn-primary mt-3" id="novaOznakaBtn2">';
    print '<i class="fas fa-plus me-2"></i>Dodaj prvu oznaku';
    print '</button>';
    print '</div>';
    print '</td>';
    print '</tr>';
}

print '</tbody>';
print '</table>';
print '</div>'; // seup-table-container

// Table footer with stats
print '<div class="seup-table-footer">';
print '<div class="seup-table-stats">';
print '<i class="fas fa-info-circle me-2"></i>';
print '<span>Prikazano <strong>' . count($oznake) . '</strong> klasifikacijskih oznaka</span>';
print '</div>';
print '<div class="seup-table-actions">';
print '<button type="button" class="seup-btn seup-btn-secondary seup-btn-sm">';
print '<i class="fas fa-download me-2"></i>Izvoz Excel';
print '</button>';
print '<button type="button" class="seup-btn seup-btn-secondary seup-btn-sm">';
print '<i class="fas fa-print me-2"></i>Ispis';
print '</button>';
print '</div>';
print '</div>';

print '</div>'; // seup-settings-card
print '</div>'; // seup-classification-container

print '</div>'; // seup-settings-content
print '</main>';

// JavaScript for enhanced functionality
print '<script src="/custom/seup/js/seup-modern.js"></script>';

?>

<script>
document.addEventListener("DOMContentLoaded", function() {
    // Navigation buttons
    const novaOznakaBtn = document.getElementById("novaOznakaBtn");
    const novaOznakaBtn2 = document.getElementById("novaOznakaBtn2");
    
    if (novaOznakaBtn) {
        novaOznakaBtn.addEventListener("click", function() {
            // Add loading state
            this.classList.add('seup-loading');
            window.location.href = "postavke.php";
        });
    }
    
    if (novaOznakaBtn2) {
        novaOznakaBtn2.addEventListener("click", function() {
            this.classList.add('seup-loading');
            window.location.href = "postavke.php";
        });
    }

    // Enhanced search functionality
    const searchInput = document.getElementById('searchInput');
    const filterVrijeme = document.getElementById('filterVrijeme');
    const filterKlasa = document.getElementById('filterKlasa');
    const filterSadrzaj = document.getElementById('filterSadrzaj');
    const tableRows = document.querySelectorAll('.seup-table-row[data-id]');

    function filterTable() {
        const searchTerm = searchInput.value.toLowerCase();
        const selectedVrijeme = filterVrijeme.value;
        const selectedKlasa = filterKlasa.value;
        const selectedSadrzaj = filterSadrzaj.value;
        let visibleCount = 0;

        tableRows.forEach(row => {
            const cells = row.querySelectorAll('.seup-table-td');
            const rowText = Array.from(cells).map(cell => cell.textContent.toLowerCase()).join(' ');
            
            // Check search term
            const matchesSearch = !searchTerm || rowText.includes(searchTerm);
            
            // Check vrijeme filter
            let matchesVrijeme = true;
            if (selectedVrijeme) {
                const vrijemeCell = cells[4]; // vrijeme_cuvanja column
                if (selectedVrijeme === '0') {
                    matchesVrijeme = vrijemeCell.textContent.includes('Trajno');
                } else {
                    matchesVrijeme = vrijemeCell.textContent.includes(selectedVrijeme + ' godina');
                }
            }

            // Check klasa filter
            let matchesKlasa = true;
            if (selectedKlasa) {
                const klasaCell = cells[1]; // klasa_broj column
                matchesKlasa = klasaCell.textContent.trim() === selectedKlasa;
            }

            // Check sadržaj filter
            let matchesSadrzaj = true;
            if (selectedSadrzaj) {
                const sadrzajCell = cells[2]; // sadrzaj column
                matchesSadrzaj = sadrzajCell.textContent.trim() === selectedSadrzaj;
            }

            if (matchesSearch && matchesVrijeme && matchesKlasa && matchesSadrzaj) {
                row.style.display = '';
                visibleCount++;
            } else {
                row.style.display = 'none';
            }
        });

        // Update stats
        const statsSpan = document.querySelector('.seup-table-stats strong');
        if (statsSpan) {
            statsSpan.textContent = visibleCount;
        }
    }

    if (searchInput) {
        searchInput.addEventListener('input', filterTable);
    }
    
    if (filterVrijeme) {
        filterVrijeme.addEventListener('change', filterTable);
    }

    if (filterKlasa) {
        filterKlasa.addEventListener('change', filterTable);
    }

    if (filterSadrzaj) {
        filterSadrzaj.addEventListener('change', filterTable);
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
            // Add loading state
            this.classList.add('seup-loading');
            // Navigate to edit page (you can implement this)
            console.log('Edit oznaka:', id);
        });
    });

    document.querySelectorAll('.seup-btn-delete').forEach(btn => {
        btn.addEventListener('click', function() {
            const id = this.dataset.id;
            if (confirm('Jeste li sigurni da želite obrisati ovu klasifikacijsku oznaku?')) {
                this.classList.add('seup-loading');
                // Implement delete functionality
                console.log('Delete oznaka:', id);
            }
        });
    });
});
</script>

<style>
/* Classification-specific styles */
.seup-classification-container {
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
}

.seup-badge-primary {
  background: var(--primary-100);
  color: var(--primary-800);
}

.seup-badge-secondary {
  background: var(--secondary-100);
  color: var(--secondary-800);
}

.seup-badge-accent {
  background: var(--accent-100);
  color: var(--accent-800);
}

.seup-badge-success {
  background: var(--success-100);
  color: var(--success-800);
}

.seup-badge-warning {
  background: var(--warning-100);
  color: var(--warning-800);
}

.seup-badge-neutral {
  background: var(--neutral-100);
  color: var(--neutral-800);
}

/* Description Cell */
.seup-description-cell {
  max-width: 200px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  cursor: help;
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

.seup-btn-delete {
  background: var(--error-100);
  color: var(--error-600);
}

.seup-btn-delete:hover {
  background: var(--error-200);
  color: var(--error-700);
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
  
  .seup-description-cell {
    max-width: 120px;
  }
}

@media (max-width: 480px) {
  .seup-table-container {
    overflow-x: auto;
  }
  
  .seup-table {
    min-width: 600px;
  }
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

/* Additional color variants */
:root {
  --primary-25: #f8faff;
  --neutral-25: #fcfcfc;
}
</style>

<?php
llxFooter();
$db->close();
?>