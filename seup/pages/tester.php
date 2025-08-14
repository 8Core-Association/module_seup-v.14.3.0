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
 *	\file       seup2/seup2index.php
 *	\ingroup    seup2
 *	\brief      Home page of seup2 top menu
 */


// Učitaj Dolibarr okruženje
$res = 0;
// Try main.inc.php into web root known defined into CONTEXT_DOCUMENT_ROOT (not always defined)
if (!$res && !empty($_SERVER["CONTEXT_DOCUMENT_ROOT"])) {
	$res = @include $_SERVER["CONTEXT_DOCUMENT_ROOT"]."/main.inc.php";
}
// Pokušaj učitati main.inc.php iz korijenskog direktorija weba, koji je određen na temelju vrijednosti SCRIPT_FILENAME.
$tmp = empty($_SERVER['SCRIPT_FILENAME']) ? '' : $_SERVER['SCRIPT_FILENAME']; $tmp2 = realpath(__FILE__); $i = strlen($tmp) - 1; $j = strlen($tmp2) - 1;
while ($i > 0 && $j > 0 && isset($tmp[$i]) && isset($tmp2[$j]) && $tmp[$i] == $tmp2[$j]) {
	$i--;
	$j--;
}
if (!$res && $i > 0 && file_exists(substr($tmp, 0, ($i + 1))."/main.inc.php")) {
	$res = @include substr($tmp, 0, ($i + 1))."/main.inc.php";
}
if (!$res && $i > 0 && file_exists(dirname(substr($tmp, 0, ($i + 1)))."/main.inc.php")) {
	$res = @include dirname(substr($tmp, 0, ($i + 1)))."/main.inc.php";
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

require_once DOL_DOCUMENT_ROOT.'/core/class/html.formfile.class.php';

// Učitaj datoteke prijevoda potrebne za stranicu
$langs->loadLangs(array("seup2@seup2"));

$action = GETPOST('action', 'aZ09');

$now = dol_now();
$max = getDolGlobalInt('MAIN_SIZE_SHORTLIST_LIMIT', 5);

// Sigurnosna provjera – zaštita ako je korisnik eksterni
$socid = GETPOST('socid', 'int');
if (isset($user->socid) && $user->socid > 0) {
	$action = '';
	$socid = $user->socid;
}

/*
 * View
 */

$form = new Form($db);
$formfile = new FormFile($db);

llxHeader("", "", '', '', 0, 0, '', '', '', 'mod-seup2 page-index');

// === BOOTSTRAP CDN DODAVANJE ===
// Meta tag za responzivnost
print '<meta name="viewport" content="width=device-width, initial-scale=1">';
// Bootstrap CSS
print '<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.5/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-SgOJa3DmI69IUzQ2PVdRZhwQ+dy64/BUtbMJw1MZ8t5HZApcHrRKUc4W0kG879m7" crossorigin="anonymous">';

// Custom style 8Core
print '<link href="../custom/seup/css/style.css" rel="stylesheet">';


//Kec ispod ovoga ti je sve što ti treba //



print '<div class="container mt-5 shadow-sm p-3 mb-5 bg-body rounded">';

// Tabovi
print '
<ul class="nav nav-tabs mb-4" id="myTab" role="tablist">
  <li class="nav-item" role="presentation">
    <button class="nav-link active" id="tab1-tab" data-bs-toggle="tab" data-bs-target="#tab1" type="button" role="tab" aria-controls="tab1" aria-selected="true">
      <i class="fas fa-home me-2"></i>Predmet
    </button>
  </li>
  <li class="nav-item" role="presentation">
    <button class="nav-link" id="tab2-tab" data-bs-toggle="tab" data-bs-target="#tab2" type="button" role="tab" aria-controls="tab2" aria-selected="false">
      <i class="fas fa-file-alt me-2"></i>Dokumenti u prilozima
    </button>
  </li>
  <li class="nav-item" role="presentation">
    <button class="nav-link" id="tab3-tab" data-bs-toggle="tab" data-bs-target="#tab3" type="button" role="tab" aria-controls="tab3" aria-selected="false">
      <i class="fas fa-search"></i>Predpregled
    </button>
  </li>
  <li class="nav-item" role="presentation">
    <button class="nav-link" id="tab4-tab" data-bs-toggle="tab" data-bs-target="#tab4" type="button" role="tab" aria-controls="tab4" aria-selected="false">
      <i class="fas fa-chart-bar me-2"></i>Šta god
    </button>
  </li>
</ul>



<div class="tab-content" id="myTabContent">
  <!-- Tab 1 -->
  <div class="tab-pane fade show active" id="tab1" role="tabpanel" aria-labelledby="tab1-tab">
    <div class="p-3 border rounded">
      <h4 class="mb-3">Klasa i urbroj</h4>
      <p>Posliži ovdije </p>
      
      <!-- Dugmici -->
      <div class="mt-3 d-flex gap-2">
        <button type="button" class="btn btn-primary btn-sm">Dugme 1</button>
        <button type="button" class="btn btn-secondary btn-sm">Dugme 2</button>
        <button type="button" class="btn btn-success btn-sm">Dugme 3</button>
      </div>
    </div>
  </div>



  <!-- Tab 2 -->
  <div class="tab-pane fade" id="tab2" role="tabpanel" aria-labelledby="tab2-tab">
    <div class="p-3 border rounded">
      <h4 class="mb-3">Akti i prilozi</h4>
      <p>Pregled kreiranih i dodanih priloga sa datumima idodavanja i kreatorom</p>
      
      <!-- Dugmici -->
      <div class="mt-3 d-flex gap-2">
        <button type="button" class="btn btn-primary btn-sm">Dugme 1</button>
        <button type="button" class="btn btn-secondary btn-sm">Dugme 2</button>
        <button type="button" class="btn btn-success btn-sm">Dugme 3</button>
      </div>
    </div>
  </div>



  <!-- Tab 3 -->
  <div class="tab-pane fade" id="tab3" role="tabpanel" aria-labelledby="tab3-tab">
    <div class="p-3 border rounded">
      <h4 class="mb-3">Predpregled omota sposa sa listom priloga</h4>
      
      <p>Bumo vidli kako</p>
      
      <!-- Dugmici -->
      <div class="mt-3 d-flex gap-2">
        <button type="button" class="btn btn-primary btn-sm">Dugme 1</button>
        <button type="button" class="btn btn-secondary btn-sm">Dugme 2</button>
        <button type="button" class="btn btn-success btn-sm">Dugme 3</button>
      </div>
    </div>
  </div>



  <!-- Tab 4 -->
  <div class="tab-pane fade" id="tab4" role="tabpanel" aria-labelledby="tab4-tab">
    <div class="p-3 border rounded">
      <h4 class="mb-3">Statistički podaci</h4>
      <p>Možda evidencije logiranja i provedenog vremena</p>
      
      <!-- Dugmici -->
      <div class="mt-3 d-flex gap-2">
        <button type="button" class="btn btn-primary btn-sm">Dugme 1</button>
        <button type="button" class="btn btn-secondary btn-sm">Dugme 2</button>
        <button type="button" class="btn btn-success btn-sm">Dugme 3</button>
      </div>
    </div>
  </div>
</div>
</div>'; 

// Ne diraj dalje ispod ništa ne mjenjaj dole je samo bootstrap cdn java scripta i dolibarr footer postavke kao što vidiš//

// Bootstrap JS bundle (uključuje Popper)
print '<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.5/dist/js/bootstrap.bundle.min.js" integrity="sha384-k6d4wzSIapyDyv1kpU366/PK5hCdSbCRGRCMv+eplOQJWyd1fbcAu9OCUj5zNLiq" crossorigin="anonymous"></script>';

// End of page
llxFooter();
$db->close();