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

// Custom naslov i dugmad
print '<div class="center" style="
  height: 100vh;
  background-image: url(\'/custom/seup/img/uredsko-poslovanje-background.jpg\');
  background-size: cover;
  background-position: center center;
">';


print '<h1 class="h1titredoc" style="color:rgb(10, 10, 10); padding-top: 100px; text-align: center;">Elektronski sustav uredskog poslovanja</h1>';
print '<div class="tabsAction" style="display: flex; justify-content: center; margin-top: 50px;">'; 


print '<a class="butAction" href="#" style="margin-left: 15px;">NOVI PREDMET</a>';
print '<a class="butAction" href="#" style="margin-left: 15px;">OTVORENI PREDMETI</a>';
print '<a class="butAction" href="#">UPUTE</a>';
print '<a class="butAction" href="#" style="margin-left: 15px;">POMOĆ</a>';
print '</div>';
print '</div>';
print '<div class="fichecenter"><div class="fichethirdleft">';
print '</div><div class="fichetwothirdright">';
print '</div></div>';

// Bootstrap JS bundle (uključuje Popper)
print '<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.5/dist/js/bootstrap.bundle.min.js" integrity="sha384-k6d4wzSIapyDyv1kpU366/PK5hCdSbCRGRCMv+eplOQJWyd1fbcAu9OCUj5zNLiq" crossorigin="anonymous"></script>';

// End of page
llxFooter();
$db->close();
