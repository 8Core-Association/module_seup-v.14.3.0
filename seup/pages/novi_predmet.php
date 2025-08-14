<?php

/**
 * Plaćena licenca
 * (c) 2025 Tomislav Galić <tomislav@8core.hr>
 * Suradnik: Marko Šimunović <marko@8core.hr>
 * Web: https://8core.hr
 * Kontakt: info@8core.hr | Tel: +385 099 851 0717
 * Sva prava pridržana. Ovaj softver je vlasnički i zabranjeno ga je
 * distribuirati ili mijenjati bez izričitog dopuštenja autora.
 */
/**
 *	\file       seup/novi_predmet.php
 *	\ingroup    seup
 *	\brief      Creation page for new predmet
 */


// Učitaj Dolibarr okruženje
$res = 0;
// Try main.inc.php into web root known defined into CONTEXT_DOCUMENT_ROOT (not always defined)
if (!$res && !empty($_SERVER["CONTEXT_DOCUMENT_ROOT"])) {
  $res = @include $_SERVER["CONTEXT_DOCUMENT_ROOT"] . "/main.inc.php";
}
// Pokušaj učitati main.inc.php iz korijenskog direktorija weba, koji je određen na temelju vrijednosti SCRIPT_FILENAME.
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
// Pokušaj učitati main.inc.php koristeći relativnu putanju

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

// Pokretanje buffera - potrebno za flush emitiranih podataka (fokusiranje na json format)
ob_start();

// Libraries
require_once DOL_DOCUMENT_ROOT . '/core/lib/admin.lib.php';
require_once DOL_DOCUMENT_ROOT . '/core/lib/files.lib.php';
require_once DOL_DOCUMENT_ROOT . '/core/lib/functions2.lib.php';
require_once DOL_DOCUMENT_ROOT . '/core/lib/usergroups.lib.php';
require_once DOL_DOCUMENT_ROOT . '/core/class/html.formfile.class.php';
require_once DOL_DOCUMENT_ROOT . '/ecm/class/ecmfiles.class.php'; // ECM klasa - za baratanje dokumentima


// Lokalne klase
require_once __DIR__ . '/../class/predmet_helper.class.php';
require_once __DIR__ . '/../class/request_handler.class.php';

// Postavljanje debug logova
error_reporting(E_ALL);
ini_set('display_errors', 1);


// Učitaj datoteke prijevoda potrebne za stranicu
$langs->loadLangs(array("seup@seup"));

$action = GETPOST('action', 'aZ09');

$now = dol_now();
$max = getDolGlobalInt('MAIN_SIZE_SHORTLIST_LIMIT', 5);

// Sigurnosna provjera – zaštita ako je korisnik eksterni
$socid = GETPOST('socid', 'int');
if (isset($user->socid) && $user->socid > 0) {
  $action = '';
  $socid = $user->socid;
}


// definiranje direktorija za privremene datoteke
define('TEMP_DIR_RELATIVE', '/temp/'); // Relative to DOL_DATA_ROOT
define('TEMP_DIR_FULL', DOL_DATA_ROOT . TEMP_DIR_RELATIVE);
define('TEMP_DIR_WEB', DOL_URL_ROOT . '/documents' . TEMP_DIR_RELATIVE);

// Ensure temp directory exists
if (!file_exists(TEMP_DIR_FULL)) {
  dol_mkdir(TEMP_DIR_FULL);
}


/*
 * View
 */

$form = new Form($db);
$formfile = new FormFile($db);

llxHeader("", "", '', '', 0, 0, '', '', '', 'mod-seup page-index');



/************************************
 ******** POST REQUESTOVI ************
 *************************************
 */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  dol_syslog('POST request', LOG_INFO);

  // OTVORI PREDMET
  if (isset($_POST['action']) && $_POST['action'] === 'otvori_predmet') {
    Request_Handler::handleOtvoriPredmet($db, $conf, $user);
    exit;
  }
}

// Registriranje requestova za autocomplete i dinamicko popunjavanje vrijednosti Sadrzaja
if (isset($_GET['ajax']) && $_GET['ajax'] == '1') {
  Request_Handler::handleCheckPredmetExists($db);
  exit;
}

if (isset($_GET['ajax']) && $_GET['ajax'] == 'autocomplete_stranka') {
  Request_Handler::handleStrankaAutocomplete($db);
  exit;
}


// Dohvat tagova iz baze 
$tags = array();
$sql = "SELECT rowid, tag FROM " . MAIN_DB_PREFIX . "a_tagovi WHERE entity = " . $conf->entity . " ORDER BY tag ASC";
$resql = $db->query($sql);
if ($resql) {
  while ($obj = $db->fetch_object($resql)) {
    $tags[] = $obj;
    dol_syslog("Tag: " . $obj->tag, LOG_DEBUG);
  }
}

$availableTagsHTML = '';
foreach ($tags as $tag) {
  $availableTagsHTML .= '<button type="button" class="btn btn-sm btn-outline-primary tag-option" 
                          data-tag-id="' . $tag->rowid . '">';
  $availableTagsHTML .= htmlspecialchars($tag->tag);
  $availableTagsHTML .= '</button>';
}

// Potrebno za kreiranje klase predmeta
// Inicijalno punjenje podataka za potrebe klase
$klasaOptions = '';
$zaposlenikOptions = '';
$code_ustanova = '';

$klasa_text = 'KLASA: OZN-SAD/GOD-DOS/RBR';
$klasaMapJson = '';

Predmet_helper::fetchDropdownData($db, $langs, $klasaOptions, $klasaMapJson, $zaposlenikOptions);

// Modern design assets
print '<meta name="viewport" content="width=device-width, initial-scale=1">';
print '<link rel="preconnect" href="https://fonts.googleapis.com">';
print '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>';
print '<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">';
print '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">';
print '<link href="/custom/seup/css/seup-modern.css" rel="stylesheet">';
print '<link href="/custom/seup/css/novi-predmet.css" rel="stylesheet">';

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
print '<h1 class="seup-settings-title">Novi Predmet</h1>';
print '<p class="seup-settings-subtitle">Kreirajte novi predmet s klasifikacijskim oznakama i povezanim dokumentima</p>';
print '</div>';

// Klasa display section
print '<div class="seup-klasa-display">';
print '<div class="seup-klasa-content">';
print '<div class="seup-klasa-icon"><i class="fas fa-sitemap"></i></div>';
print '<div class="seup-klasa-text">';
print '<h5 class="seup-klasa-title">Trenutna klasa predmeta</h5>';
print '<p class="seup-klasa-value" id="klasa-value">' . $klasa_text . '</p>';
print '</div>';
print '</div>';
print '</div>';

// Main form container
print '<div class="seup-form-container">';

// Left card - Parameters
print '<div class="seup-settings-card animate-fade-in-up">';
print '<div class="seup-card-header">';
print '<div class="seup-card-icon"><i class="fas fa-cogs"></i></div>';
print '<h3 class="seup-card-title">Parametri Predmeta</h3>';
print '<p class="seup-card-description">Odaberite klasifikaciju i osnovne parametre</p>';
print '</div>';

print '<form method="post" action="' . $_SERVER['PHP_SELF'] . '" class="seup-form">';
print '<div class="seup-form-grid">';

print '<div class="seup-form-group">';
print '<label for="klasa_br" class="seup-label"><i class="fas fa-layer-group me-2"></i>Klasa broj</label>';
print '<select name="klasa_br" id="klasa_br" class="seup-select" required>';
print $klasaOptions;
print '</select>';
print '</div>';

print '<div class="seup-form-group">';
print '<label for="sadrzaj" class="seup-label"><i class="fas fa-list me-2"></i>Sadržaj</label>';
print '<select name="sadrzaj" id="sadrzaj" class="seup-select" required>';
print '<option value="">' . $langs->trans("Odaberi Sadrzaj") . '</option>';
print '</select>';
print '</div>';

print '</div>'; // seup-form-grid

print '<div class="seup-form-grid">';

print '<div class="seup-form-group">';
print '<label for="dosjeBroj" class="seup-label"><i class="fas fa-folder me-2"></i>Dosje broj</label>';
print '<select name="dosjeBroj" id="dosjeBroj" class="seup-select" required>';
print '<option value="">' . $langs->trans("Odaberi Dosje Broj") . '</option>';
print '</select>';
print '</div>';

print '<div class="seup-form-group">';
print '<label for="zaposlenik" class="seup-label"><i class="fas fa-user me-2"></i>Zaposlenik</label>';
print '<select class="seup-select" id="zaposlenik" name="zaposlenik" required>';
print $zaposlenikOptions;
print '</select>';
print '</div>';

print '</div>'; // seup-form-grid

print '<div class="seup-form-group">';
print '<label for="stranka" class="seup-label"><i class="fas fa-building me-2"></i>Stranka</label>';
print '<div class="seup-stranka-container">';
print '<select class="seup-select" id="stranka" name="stranka" disabled style="flex: 1;"></select>';
print '<div class="seup-checkbox-container">';
print '<input type="checkbox" class="seup-checkbox" id="strankaCheck" autocomplete="off">';
print '<label class="seup-checkbox-label" for="strankaCheck">Otvorila stranka?</label>';
print '</div>';
print '</div>';
print '<div id="strankaDatumContainer" class="seup-date-container" style="display:none;">';
print '<label for="strankaDatumOtvaranja" class="seup-label">Datum otvaranja od strane stranke</label>';
print '<button type="button" class="seup-date-btn" id="strankaDateBtn">';
print '<i class="fas fa-calendar me-2"></i>Odaberi datum';
print '</button>';
print '<input type="hidden" name="strankaDatumOtvaranja" id="strankaDatumOtvaranja">';
print '<div id="strankaDateError" class="seup-error-message" style="display: none;">Odaberite datum otvaranja predmeta!</div>';
print '</div>';
print '<div id="strankaError" class="seup-error-message" style="display: none;">Odaberite stranku!</div>';
print '</div>';

print '</form>';
print '</div>'; // Left card

// Right card - Details
print '<div class="seup-settings-card animate-fade-in-up">';
print '<div class="seup-card-header">';
print '<div class="seup-card-icon"><i class="fas fa-file-alt"></i></div>';
print '<h3 class="seup-card-title">Detalji Predmeta</h3>';
print '<p class="seup-card-description">Unesite naziv, datum i oznake predmeta</p>';
print '</div>';

print '<div class="seup-form">';

print '<div class="seup-form-group">';
print '<label for="naziv" class="seup-label"><i class="fas fa-heading me-2"></i>Naziv predmeta</label>';
print '<textarea class="seup-textarea" id="naziv" name="naziv" rows="4" maxlength="500" placeholder="Unesite naziv predmeta (maksimalno 500 znakova)"></textarea>';
print '<div class="seup-char-counter" id="charCounter">0 / 500</div>';
print '</div>';

print '<div class="seup-form-group">';
print '<label for="datumOtvaranja" class="seup-label"><i class="fas fa-calendar me-2"></i>Datum otvaranja predmeta</label>';
print '<button type="button" class="seup-date-btn" id="datumOtvaranjaBtn">';
print '<i class="fas fa-calendar"></i> Odaberi datum';
print '</button>';
print '<input type="hidden" name="datumOtvaranja" id="datumOtvaranja">';
print '<div class="seup-help-text"><i class="fas fa-info-circle"></i> Ostavite prazno za današnji datum</div>';
print '</div>';

print '<div class="seup-form-group">';
print '<label class="seup-label"><i class="fas fa-tags me-2"></i>Oznake</label>';
print '<button type="button" class="seup-tags-btn" id="tagsBtn">';
print '<i class="fas fa-tags"></i> Odaberi oznake';
print '</button>';
print '<div class="seup-selected-tags" id="selectedTagsContainer">';
print '<div class="text-muted small">Nema odabranih oznaka</div>';
print '</div>';
print '</div>';

print '<div class="seup-form-actions">';
print '<button type="button" class="seup-btn seup-btn-primary" id="otvoriPredmetBtn">';
print '<i class="fas fa-plus"></i> Otvori Predmet';
print '</button>';
print '</div>';

print '</div>'; // seup-form
print '</div>'; // Right card

print '</div>'; // seup-form-container

print '</div>'; // seup-settings-content

// Date Picker Modal
print '<div class="seup-modal" id="dateModal">';
print '<div class="seup-modal-content">';
print '<div class="seup-modal-header">';
print '<h5 class="seup-modal-title"><i class="fas fa-calendar"></i> Odaberi datum</h5>';
print '<button type="button" class="seup-modal-close" id="closeDateModal">&times;</button>';
print '</div>';
print '<div class="seup-modal-body">';
print '<div class="calendar-header">';
print '<div class="calendar-year-month">';
print '<select id="yearSelect" class="seup-select calendar-year-select"></select>';
print '<select id="monthSelect" class="seup-select calendar-month-select"></select>';
print '</div>';
print '<div class="calendar-nav-buttons">';
print '<button type="button" class="seup-btn seup-btn-secondary seup-btn-sm" id="prevMonth">';
print '<i class="fas fa-chevron-left"></i>';
print '</button>';
print '<button type="button" class="seup-btn seup-btn-secondary seup-btn-sm" id="nextMonth">';
print '<i class="fas fa-chevron-right"></i>';
print '</button>';
print '</div>';
print '</div>';
print '<div class="calendar-grid" id="calendarGrid"></div>';
print '</div>';
print '<div class="seup-modal-footer">';
print '<button type="button" class="seup-btn seup-btn-secondary" id="cancelDate">Odustani</button>';
print '<button type="button" class="seup-btn seup-btn-primary" id="confirmDate">Potvrdi</button>';
print '</div>';
print '</div>';
print '</div>';

// Tags Modal
print '<div class="seup-modal" id="tagsModal">';
print '<div class="seup-modal-content">';
print '<div class="seup-modal-header">';
print '<h5 class="seup-modal-title"><i class="fas fa-tags"></i> Odaberi oznake</h5>';
print '<button type="button" class="seup-modal-close" id="closeTagsModal">&times;</button>';
print '</div>';
print '<div class="seup-modal-body">';
print '<div class="seup-tags-grid" id="tagsGrid">';
foreach ($tags as $tag) {
    print '<div class="seup-tag-option" data-tag-id="' . $tag->rowid . '">';
    print '<i class="fas fa-tag"></i> ' . htmlspecialchars($tag->tag);
    print '</div>';
}
print '</div>';
print '</div>';
print '<div class="seup-modal-footer">';
print '<button type="button" class="seup-btn seup-btn-secondary" id="cancelTags">Odustani</button>';
print '<button type="button" class="seup-btn seup-btn-primary" id="confirmTags">Potvrdi</button>';
print '</div>';
print '</div>';
print '</div>';

print '</main>';

// JavaScript for enhanced functionality
print '<script src="/custom/seup/js/seup-modern.js"></script>';

?>

<script>
document.addEventListener("DOMContentLoaded", function() {
    // Get the select elements and klasa value element
    const klasaMap = JSON.parse('<?php echo $klasaMapJson; ?>');
    console.log("KlasaMap loaded:", klasaMap);
    
    const klasaSelect = document.getElementById("klasa_br");
    const sadrzajSelect = document.getElementById("sadrzaj");
    const dosjeSelect = document.getElementById("dosjeBroj");
    const zaposlenikSelect = document.getElementById("zaposlenik");
    const klasaValue = document.getElementById("klasa-value");
    const otvoriPredmetBtn = document.getElementById("otvoriPredmetBtn");
    const nazivTextarea = document.getElementById("naziv");
    const charCounter = document.getElementById("charCounter");

    // State for keeping track of current values
    let currentValues = {
        klasa: "",
        sadrzaj: "",
        dosje: "",
        rbr: "1"
    };

    let year = new Date().getFullYear();
    year = year.toString().slice(-2);

    // Character counter for naziv
    if (nazivTextarea && charCounter) {
        nazivTextarea.addEventListener('input', function() {
            const length = this.value.length;
            charCounter.textContent = `${length} / 500`;
            
            if (length > 450) {
                charCounter.classList.add('danger');
                charCounter.classList.remove('warning');
            } else if (length > 400) {
                charCounter.classList.add('warning');
                charCounter.classList.remove('danger');
            } else {
                charCounter.classList.remove('warning', 'danger');
            }
        });
    }

    function updateKlasaValue() {
        const klasa = currentValues.klasa || "OZN";
        const sadrzaj = currentValues.sadrzaj || "SAD";
        const selectedDosje = dosjeSelect.value || "DOS";
        const rbr = currentValues.rbr || "1";

        const updatedText = `KLASA: ${klasa}-${sadrzaj}/${year}-${selectedDosje}/${rbr}`;
        klasaValue.textContent = updatedText;
    }

    function checkIfPredmetExists() {
        const klasa = klasaSelect.value || "OZN";
        const sadrzaj = sadrzajSelect.value || "SAD";
        const dosje_br = dosjeSelect.value || "DOS";
        
        console.log("Checking if predmet exists");
        
        if (klasa !== "OZN" && sadrzaj !== "SAD" && dosje_br !== "DOS") {
            fetch(
                "novi_predmet.php?ajax=1&" +
                "klasa_br=" + encodeURIComponent(klasa) +
                "&sadrzaj=" + encodeURIComponent(sadrzaj) +
                "&dosje_br=" + encodeURIComponent(dosje_br) +
                "&god=" + encodeURIComponent(year), {
                    headers: {
                        "Accept": "application/json"
                    }
                }
            )
            .then(response => response.json())
            .then(data => {
                if (data.status === "exists" || data.status === "inserted") {
                    currentValues.rbr = data.next_rbr;
                    updateKlasaValue();
                    
                    if (data.status === "exists") {
                        console.log("Ovakav predmet postoji. Generiram sljedeci redni broj predmeta.");
                    }
                } else {
                    console.log("Predmet does not exist, ready to create new one." + data.status);
                }
            })
            .catch(error => console.error("Error checking predmet:", error));
        }
    }

    function resetKlasaDisplay() {
        currentValues = {
            klasa: "",
            sadrzaj: "",
            dosje: "",
            rbr: "1"
        };
        klasaSelect.value = "";
        sadrzajSelect.innerHTML = `<option value="">${sadrzajSelect.dataset.placeholder || 'Odaberi Sadrzaj'}</option>`;
        dosjeSelect.innerHTML = `<option value="">${dosjeSelect.dataset.placeholder || 'Odaberi Dosje Broj'}</option>`;
        zaposlenikSelect.value = "";
        updateKlasaValue();
    }

    // Event listeners for dropdowns
    if (klasaSelect) {
        klasaSelect.addEventListener("change", function() {
            console.log("Selected klasa:", this.value);
            currentValues.klasa = this.value || "";
            currentValues.dosje = "";

            // Reset sadrzaj dropdown
            sadrzajSelect.innerHTML = `<option value="">Odaberi Sadrzaj</option>`;
            dosjeSelect.innerHTML = `<option value="">Odaberi Dosje Broj</option>`;

            // Populate new options based on selected klasa
            if (this.value && klasaMap[this.value]) {
                const sadrzajValues = Object.keys(klasaMap[this.value]);
                sadrzajValues.forEach(sadrzaj => {
                    const option = new Option(sadrzaj, sadrzaj);
                    sadrzajSelect.appendChild(option);
                });
            }

            updateKlasaValue();
            checkIfPredmetExists();
        });
    }

    if (sadrzajSelect) {
        sadrzajSelect.addEventListener("change", function() {
            console.log("Selected sadrzaj:", this.value);
            dosjeSelect.innerHTML = `<option value="">Odaberi Dosje Broj</option>`;

            currentValues.sadrzaj = this.value || "SAD";
            currentValues.dosje = "";

            const klasa = klasaSelect.value;
            const sadrzaj = this.value;
            
            if (klasa && sadrzaj && klasaMap[klasa] && klasaMap[klasa][sadrzaj]) {
                klasaMap[klasa][sadrzaj].forEach(dosje => {
                    const option = new Option(dosje, dosje);
                    dosjeSelect.appendChild(option);
                });
            }
            updateKlasaValue();
            checkIfPredmetExists();
        });
    }

    if (dosjeSelect) {
        dosjeSelect.addEventListener("change", function() {
            currentValues.dosje = this.value || "";
            updateKlasaValue();
            checkIfPredmetExists();
        });
    }

    // Date Picker Modal Functionality
    let currentDateTarget = null;
    let selectedDate = null;
    let currentMonth = new Date().getMonth();
    let currentYear = new Date().getFullYear();

    const monthNames = [
        'Siječanj', 'Veljača', 'Ožujak', 'Travanj', 'Svibanj', 'Lipanj',
        'Srpanj', 'Kolovoz', 'Rujan', 'Listopad', 'Studeni', 'Prosinac'
    ];

    // Generate year and month selects
    function populateYearMonthSelects() {
        const yearSelect = document.getElementById('yearSelect');
        const monthSelect = document.getElementById('monthSelect');
        
        // Populate years (current year ± 5)
        const currentYear = new Date().getFullYear();
        yearSelect.innerHTML = '';
        for (let year = currentYear - 5; year <= currentYear + 5; year++) {
            const option = new Option(year, year);
            if (year === currentYear) option.selected = true;
            yearSelect.appendChild(option);
        }
        
        // Populate months
        monthSelect.innerHTML = '';
        monthNames.forEach((month, index) => {
            const option = new Option(month, index);
            if (index === currentMonth) option.selected = true;
            monthSelect.appendChild(option);
        });
        
        // Event listeners for year/month changes
        yearSelect.addEventListener('change', function() {
            currentYear = parseInt(this.value);
            generateCalendar();
        });
        
        monthSelect.addEventListener('change', function() {
            currentMonth = parseInt(this.value);
            generateCalendar();
        });
    }

    function openDateModal(targetButton, hiddenInput) {
        currentDateTarget = { button: targetButton, input: hiddenInput };
        const modal = document.getElementById('dateModal');
        modal.classList.add('show');
        populateYearMonthSelects();
        generateCalendar();
    }

    function closeDateModal() {
        const modal = document.getElementById('dateModal');
        modal.classList.remove('show');
        currentDateTarget = null;
        selectedDate = null;
    }

    function generateCalendar() {
        const grid = document.getElementById('calendarGrid');
        
        // Clear previous calendar
        grid.innerHTML = '';
        
        // Add day headers
        const dayHeaders = ['Pon', 'Uto', 'Sri', 'Čet', 'Pet', 'Sub', 'Ned'];
        dayHeaders.forEach(day => {
            const dayElement = document.createElement('div');
            dayElement.className = 'calendar-day-header';
            dayElement.textContent = day;
            grid.appendChild(dayElement);
        });
        
        // Get first day of month and number of days
        const firstDay = new Date(currentYear, currentMonth, 1);
        const lastDay = new Date(currentYear, currentMonth + 1, 0);
        const daysInMonth = lastDay.getDate();
        
        // Adjust for Monday start (0 = Sunday, 1 = Monday, etc.)
        let startDay = firstDay.getDay();
        startDay = startDay === 0 ? 6 : startDay - 1;
        
        // Add empty cells for days before month starts
        for (let i = 0; i < startDay; i++) {
            const emptyElement = document.createElement('div');
            emptyElement.className = 'calendar-empty';
            grid.appendChild(emptyElement);
        }
        
        // Add days of month
        const today = new Date();
        for (let day = 1; day <= daysInMonth; day++) {
            const dayElement = document.createElement('div');
            dayElement.className = 'calendar-date';
            dayElement.textContent = day;
            dayElement.dataset.date = `${currentYear}-${(currentMonth + 1).toString().padStart(2, '0')}-${day.toString().padStart(2, '0')}`;
            
            // Mark today
            if (currentYear === today.getFullYear() && 
                currentMonth === today.getMonth() && 
                day === today.getDate()) {
                dayElement.classList.add('today');
            }
            
            dayElement.addEventListener('click', function() {
                // Remove previous selection
                document.querySelectorAll('.calendar-date.selected').forEach(el => {
                    el.classList.remove('selected');
                });
                
                // Add selection to clicked date
                this.classList.add('selected');
                selectedDate = this.dataset.date;
            });
            
            grid.appendChild(dayElement);
        }
    }

    // Date modal event listeners
    document.getElementById('datumOtvaranjaBtn').addEventListener('click', function() {
        openDateModal(this, document.getElementById('datumOtvaranja'));
    });

    document.getElementById('strankaDateBtn').addEventListener('click', function() {
        openDateModal(this, document.getElementById('strankaDatumOtvaranja'));
    });

    document.getElementById('closeDateModal').addEventListener('click', closeDateModal);
    document.getElementById('cancelDate').addEventListener('click', closeDateModal);

    document.getElementById('confirmDate').addEventListener('click', function() {
        if (selectedDate && currentDateTarget) {
            const date = new Date(selectedDate);
            const formattedDate = `${date.getDate().toString().padStart(2, '0')}.${(date.getMonth() + 1).toString().padStart(2, '0')}.${date.getFullYear()}`;
            
            currentDateTarget.button.innerHTML = `<i class="fas fa-calendar me-2"></i>${formattedDate}`;
            currentDateTarget.button.classList.add('selected');
            currentDateTarget.input.value = selectedDate;
        }
        closeDateModal();
    });

    document.getElementById('prevMonth').addEventListener('click', function() {
        currentMonth--;
        if (currentMonth < 0) {
            currentMonth = 11;
            currentYear--;
        }
        generateCalendar();
    });

    document.getElementById('nextMonth').addEventListener('click', function() {
        currentMonth++;
        if (currentMonth > 11) {
            currentMonth = 0;
            currentYear++;
        }
        generateCalendar();
    });

    // Tags Modal Functionality
    let selectedTagIds = new Set();

    function openTagsModal() {
        const modal = document.getElementById('tagsModal');
        modal.classList.add('show');
        
        // Update visual state based on current selection
        document.querySelectorAll('.seup-tag-option').forEach(option => {
            const tagId = option.dataset.tagId;
            if (selectedTagIds.has(tagId)) {
                option.classList.add('selected');
            } else {
                option.classList.remove('selected');
            }
        });
    }

    function closeTagsModal() {
        const modal = document.getElementById('tagsModal');
        modal.classList.remove('show');
    }

    function updateSelectedTagsDisplay() {
        const container = document.getElementById('selectedTagsContainer');
        container.innerHTML = '';
        
        if (selectedTagIds.size === 0) {
            container.innerHTML = '<div class="text-muted small">Nema odabranih oznaka</div>';
        } else {
            selectedTagIds.forEach(tagId => {
                const tagOption = document.querySelector(`[data-tag-id="${tagId}"]`);
                if (tagOption) {
                    const tagName = tagOption.textContent.trim();
                    const tagElement = document.createElement('div');
                    tagElement.className = 'seup-selected-tag';
                    tagElement.innerHTML = `
                        <i class="fas fa-tag"></i> 
                        ${tagName}
                        <button type="button" class="seup-tag-remove" data-tag-id="${tagId}">
                            <i class="fas fa-times"></i>
                        </button>
                    `;
                    container.appendChild(tagElement);
                }
            });
        }
    }

    // Tags modal event listeners
    document.getElementById('tagsBtn').addEventListener('click', openTagsModal);
    document.getElementById('closeTagsModal').addEventListener('click', closeTagsModal);
    document.getElementById('cancelTags').addEventListener('click', closeTagsModal);

    document.getElementById('confirmTags').addEventListener('click', function() {
        updateSelectedTagsDisplay();
        
        // Update button text
        const tagsBtn = document.getElementById('tagsBtn');
        if (selectedTagIds.size === 0) {
            tagsBtn.innerHTML = '<i class="fas fa-tags"></i> Odaberi oznake';
        } else {
            tagsBtn.innerHTML = `<i class="fas fa-tags"></i> Odabrano: ${selectedTagIds.size} oznaka`;
        }
        
        closeTagsModal();
    });

    // Tag selection in modal
    document.getElementById('tagsGrid').addEventListener('click', function(e) {
        if (e.target.closest('.seup-tag-option')) {
            const option = e.target.closest('.seup-tag-option');
            const tagId = option.dataset.tagId;
            
            if (selectedTagIds.has(tagId)) {
                selectedTagIds.delete(tagId);
                option.classList.remove('selected');
            } else {
                selectedTagIds.add(tagId);
                option.classList.add('selected');
            }
        }
    });

    // Remove tag from selection
    document.addEventListener('click', function(e) {
        if (e.target.closest('.seup-tag-remove')) {
            const tagId = e.target.closest('.seup-tag-remove').dataset.tagId;
            selectedTagIds.delete(tagId);
            updateSelectedTagsDisplay();
            
            // Update button text
            const tagsBtn = document.getElementById('tagsBtn');
            if (selectedTagIds.size === 0) {
                tagsBtn.innerHTML = '<i class="fas fa-tags"></i> Odaberi oznake';
            } else {
                tagsBtn.innerHTML = `<i class="fas fa-tags"></i> Odabrano: ${selectedTagIds.size} oznaka`;
            }
        }
    });

    // Stranka functionality
    document.getElementById('strankaCheck').addEventListener('change', function() {
        const selectField = document.getElementById('stranka');
        const errorDiv = document.getElementById('strankaError');
        const container = document.getElementById('strankaDatumContainer');

        if (this.checked) {
            selectField.disabled = false;
            selectField.required = true;
            errorDiv.style.display = 'none';
            selectField.classList.remove('is-invalid');
            container.style.display = 'block';
            selectField.focus();
        } else {
            selectField.disabled = true;
            selectField.required = false;
            selectField.innerHTML = '';
            errorDiv.style.display = 'none';
            selectField.classList.remove('is-invalid');
            container.style.display = 'none';
        }
    });

    // Close modals when clicking outside
    document.addEventListener('click', function(e) {
        if (e.target.classList.contains('seup-modal')) {
            e.target.classList.remove('show');
        }
    });

    // Initial update
    updateKlasaValue();

    // Form submission
    if (otvoriPredmetBtn) {
        otvoriPredmetBtn.addEventListener("click", function() {
            const klasa = klasaSelect.value;
            const sadrzaj = sadrzajSelect.value;
            const dosje = dosjeSelect.value;
            const zaposlenik = zaposlenikSelect.value;
            const naziv = document.getElementById("naziv").value;

            // Validation
            let isValid = true;
            const missingFields = [];

            if (!klasa) missingFields.push("Klasa broj");
            if (!sadrzaj) missingFields.push("Sadržaj");
            if (!dosje) missingFields.push("Dosje broj");
            if (!zaposlenik) missingFields.push("Zaposlenik");
            if (!naziv.trim()) missingFields.push("Naziv predmeta");

            // Stranka validation
            const strankaCheckbox = document.getElementById('strankaCheck');
            const strankaField = document.getElementById('stranka');
            const strankaError = document.getElementById('strankaError');
            const strankaDateError = document.getElementById('strankaDateError');

            if (strankaCheckbox.checked) {
                if (!strankaField.value) {
                    isValid = false;
                    strankaField.classList.add('is-invalid');
                    strankaError.style.display = 'block';
                }

                const strankaDateInput = document.getElementById('strankaDatumOtvaranja');
                if (!strankaDateInput.value) {
                    isValid = false;
                    strankaDateError.style.display = 'block';
                }
            }

            if (missingFields.length > 0) {
                isValid = false;
                const errorMessage = "Molimo vas da popunite sva obavezna polja:\n\n" +
                    missingFields.map(field => `- ${field}`).join("\n");
                alert(errorMessage);
            }

            if (!isValid) return;

            // Add loading state
            this.classList.add('seup-loading');

            const formData = new FormData();
            formData.append("action", "otvori_predmet");
            formData.append("klasa_br", klasa);
            formData.append("sadrzaj", sadrzaj);
            formData.append("dosje_broj", dosje);
            formData.append("zaposlenik", zaposlenik);
            formData.append("god", year);
            formData.append("naziv", naziv);

            // Add stranka data if checked
            if (strankaCheckbox.checked) {
                formData.append("stranka", strankaField.value.trim());
                const strankaDate = document.getElementById('strankaDatumOtvaranja').value;
                if (strankaDate) {
                    formData.append("strankaDatumOtvaranja", strankaDate);
                }
            }

            // Add main date
            const datumInput = document.getElementById('datumOtvaranja');
            let datumOtvaranjaTimestamp = null;

            if (datumInput.value) {
                const date = new Date(datumInput.value);
                const now = new Date();
                datumOtvaranjaTimestamp = 
                    `${date.getFullYear()}-${(date.getMonth() + 1).toString().padStart(2, '0')}-${date.getDate().toString().padStart(2, '0')} ` +
                    `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}`;
            } else {
                const now = new Date();
                datumOtvaranjaTimestamp =
                    `${now.getFullYear()}-${(now.getMonth() + 1).toString().padStart(2, '0')}-${now.getDate().toString().padStart(2, '0')} ` +
                    `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}`;
            }

            formData.append("datumOtvaranja", datumOtvaranjaTimestamp);

            // Add selected tags
            selectedTagIds.forEach(tagId => {
                formData.append("tags[]", tagId);
            });

            fetch("novi_predmet.php", {
                method: "POST",
                body: formData
            })
            .then(async response => {
                const responseText = await response.text();
                try {
                    return JSON.parse(responseText);
                } catch (e) {
                    throw new Error(`Invalid JSON response: ${responseText.substring(0, 100)}...`);
                }
            })
            .then(data => {
                if (data.success) {
                    // Show success message
                    showMessage("Predmet je uspješno otvoren!", 'success');
                    
                    // Reset form
                    resetKlasaDisplay();
                    document.getElementById("naziv").value = "";
                    charCounter.textContent = "0 / 500";
                    charCounter.classList.remove('warning', 'danger');
                    
                    // Reset date buttons
                    document.getElementById('datumOtvaranjaBtn').innerHTML = '<i class="fas fa-calendar"></i> Odaberi datum';
                    document.getElementById('datumOtvaranjaBtn').classList.remove('selected');
                    document.getElementById('datumOtvaranja').value = '';
                    
                    // Reset tags
                    selectedTagIds.clear();
                    updateSelectedTagsDisplay();
                    document.getElementById('tagsBtn').innerHTML = '<i class="fas fa-tags"></i> Odaberi oznake';
                    
                    // Reset stranka
                    const strankaCheckbox = document.getElementById('strankaCheck');
                    strankaCheckbox.checked = false;
                    strankaCheckbox.dispatchEvent(new Event('change'));
                } else {
                    showMessage("Greška pri otvaranju predmeta: " + data.error, 'error');
                }
            })
            .catch(error => {
                console.error("Error:", error);
                showMessage("Došlo je do greške: " + error.message, 'error');
            })
            .finally(() => {
                // Remove loading state
                this.classList.remove('seup-loading');
            });
        });
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
            <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-triangle'}"></i> 
            ${message}
        `;

        setTimeout(() => {
            messageEl.classList.remove('show');
        }, duration);
    };

    // Initial update to set the default state
    updateKlasaValue();
});
</script>

<?php
llxFooter();
$db->close();
?>