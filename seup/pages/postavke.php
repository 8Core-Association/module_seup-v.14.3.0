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
 *    \file       seup/seupindex.php
 *    \ingroup    seup
 *    \brief      Home page of seup top menu
 */


// Učitaj Dolibarr okruženje
$res = 0;
// Try main.inc.php into web root known defined into CONTEXT_DOCUMENT_ROOT (not always defined)
if (!$res && !empty($_SERVER["CONTEXT_DOCUMENT_ROOT"])) {
  $res = @include $_SERVER["CONTEXT_DOCUMENT_ROOT"] . "/main.inc.php";
}
// Pokušaj učitati main.inc.php iz korijenskog direktorija weba
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

// Omoguci debugiranje php skripti
error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once DOL_DOCUMENT_ROOT . '/core/class/html.formfile.class.php';

if ($res) {
  // include Form class za token
  if (file_exists("../../../core/class/html.form.class.php")) {
    if (!dol_include_once('/core/class/html.form.class.php')) {
      die("Include of form fails");
    }
  }
} else {
  die("Error: Unable to include main.inc.php");
}
// Učitaj prijevode
$langs->loadLangs(array("seup@seup"));

$action = GETPOST('action', 'aZ09');

$now = dol_now();
$max = getDolGlobalInt('MAIN_SIZE_SHORTLIST_LIMIT', 5);
ob_start(); // Kontrolira buffer
// Sigurnosne provjere
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

llxHeader("", "SEUP - Postavke", '', '', 0, 0, '', '', '', 'mod-seup page-postavke');

// Modern design assets
print '<meta name="viewport" content="width=device-width, initial-scale=1">';
print '<link rel="preconnect" href="https://fonts.googleapis.com">';
print '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>';
print '<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">';
print '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">';
print '<link href="/custom/seup/css/seup-modern.css" rel="stylesheet">';

require_once __DIR__ . '/../class/klasifikacijska_oznaka.class.php';
require_once __DIR__ . '/../class/oznaka_ustanove.class.php';
require_once __DIR__ . '/../class/interna_oznaka_korisnika.class.php';

// Import JS skripti
global $hookmanager;
$messagesFile = DOL_URL_ROOT . '/custom/seup/js/messages.js';
$hookmanager->initHooks(array('seup'));
print '<script src="' . $messagesFile . '"></script>';

// importanje klasa za rad s podacima: 
/*
**************************************
RAD S BAZOM 
**************************************
*/
// Provjeravamo da li u bazi vec postoji OZNAKA USTANOVE, ako postoji napunit cemo formu podacima
global $db;

// Provjera i Loadanje vrijednosti oznake ustanove pri loadu stranice
$podaci_postoje = null;
$sql = "SELECT ID_ustanove, singleton, code_ustanova, name_ustanova FROM " . MAIN_DB_PREFIX . "a_oznaka_ustanove WHERE  singleton = 1 LIMIT 1";
$resql = $db->query($sql);
$ID_ustanove = 0;
if ($resql && $db->num_rows($resql) > 0) {
  $podaci_postoje = $db->fetch_object($resql);
  $ID_ustanove = $podaci_postoje->ID_ustanove;
  dol_syslog("Podaci o oznaci ustanove su ucitani iz baze: " . $ID_ustanove, LOG_INFO);
}

// Provjera i Loadanje korisnika pri loadu stranice
require_once DOL_DOCUMENT_ROOT . '/user/class/user.class.php';

$listUsers = [];
$userStatic = new User($db);

// Dohvati sve aktivne korisnike
$sql = "SELECT rowid FROM " . MAIN_DB_PREFIX . "user WHERE statut = 1 ORDER BY lastname ASC";
$resql = $db->query($sql);
if ($resql) {
  while ($obj = $db->fetch_object($resql)) {
    $userStatic->fetch($obj->rowid);
    $listUsers[] = clone $userStatic;
  }
} else {
  echo $db->lasterror();
}

/*************************************
UNOSENJE PODATAKA IZ FORME U TABLICE
 **************************************/
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  //TODO rijesi sigurnisni token - ne registriraju se metode Form klase. PROVJERI INICIJALNIZACIJU 
  // Provjera sigurnosnog tokena - sprijecava ponavljanje unosa pri refreshu i stiti protiv CSRF napada
  // if (!dol_check_token(GETPOST('token', 'alpha'))) {
  //   setEventMessages($langs->trans("ErrorBadCSRFToken"), null, 'errors');
  //   exit;
  // }

  // 1. Dodavanje interne oznake korisnika 
  if (isset($_POST['action_oznaka']) && $_POST['action_oznaka'] === 'add') {
    // Get form values
    $interna_oznaka_korisnika = new Interna_oznaka_korisnika();
    $interna_oznaka_korisnika->setIme_prezime(GETPOST('ime_user', 'alphanohtml'));
    $interna_oznaka_korisnika->setRbr_korisnika(GETPOST('redni_broj', 'int'));
    $interna_oznaka_korisnika->setRadno_mjesto_korisnika(GETPOST('radno_mjesto_korisnika', 'alphanohtml'));
    dol_syslog("User full name: " . $interna_oznaka_korisnika->getIme_prezime(), LOG_INFO);

    // Validate inputs
    if (empty($interna_oznaka_korisnika->getIme_prezime()) || empty($interna_oznaka_korisnika->getRbr_korisnika()) || empty($interna_oznaka_korisnika->getRadno_mjesto_korisnika())) {
      setEventMessages($langs->trans("All fields are required"), null, 'errors');
    } elseif (!preg_match('/^\d{1,2}$/', $interna_oznaka_korisnika->getRbr_korisnika())) {
      setEventMessages($langs->trans("Invalid serial number (vrijednosti moraju biti u rasponu 0 - 99)"), null, 'errors');
    } else {

      // Provjera da li postoji vec korisnik s tim rednim brojem
      $sqlCheck = "SELECT COUNT(*) as cnt FROM " . MAIN_DB_PREFIX . "a_interna_oznaka_korisnika WHERE rbr = '" . $db->escape($interna_oznaka_korisnika->getRbr_korisnika()) . "'";
      $resCheck = $db->query($sqlCheck);

      if ($resCheck) {
        $obj = $db->fetch_object($resCheck);
        if ($obj->cnt > 0) {
          setEventMessages($langs->trans("Korisnik s tim rednim brojem vec postoji u bazi"), null, 'errors');
        } else {

          $db->begin();
          // Insert into database
          $sql = "INSERT INTO " . MAIN_DB_PREFIX . "a_interna_oznaka_korisnika 
                      (ID_ustanove, ime_prezime, rbr, naziv) 
                      VALUES (
                    " . (int)$ID_ustanove . ", 
                    '" . $db->escape($interna_oznaka_korisnika->getIme_prezime()) . "',
                    '" . $db->escape($interna_oznaka_korisnika->getRbr_korisnika()) . "',
                    '" . $db->escape($interna_oznaka_korisnika->getRadno_mjesto_korisnika()) . "'                
                )";

          if ($db->query($sql)) {
            $db->commit();
            setEventMessages($langs->trans("Intena Oznaka Korisnika uspjesno dodana"), null, 'mesgs');
          } else {
            setEventMessages($langs->trans("Database error: ") . $db->lasterror(), null, 'errors');
          }
        }
      }
    }
  }
  if (isset($_POST['action_oznaka']) && $_POST['action_oznaka'] === 'update') {
    $originalCombination = json_decode(GETPOST('original_combination', 'restricthtml'), true);

    // Check if we have a valid combination
    if (
      !$originalCombination ||
      !isset($originalCombination['klasa_br']) ||
      !isset($originalCombination['sadrzaj']) ||
      !isset($originalCombination['dosje_br'])
    ) {

      setEventMessages($langs->trans("ErrorMissingOriginalCombination"), null, 'errors');
      $error++;
    } else {
      // Escape original values
      $origKlasa = $db->escape($originalCombination['klasa_br']);
      $origSadrzaj = $db->escape($originalCombination['sadrzaj']);
      $origDosje = $db->escape($originalCombination['dosje_br']);

      // Check if the original record exists
      $sqlProvjera = "SELECT ID_klasifikacijske_oznake 
                    FROM " . MAIN_DB_PREFIX . "a_klasifikacijska_oznaka 
                    WHERE klasa_broj = '$origKlasa'
                    AND sadrzaj = '$origSadrzaj'
                    AND dosje_broj = '$origDosje'";

      $rezultatProvjere = $db->query($sqlProvjera);

      if ($db->num_rows($rezultatProvjere) <= 0) {
        setEventMessages($langs->trans("KombinacijaNePostoji"), null, 'errors');
        $error++;
      } else {
        $update_array = array();
        $where_array = array();

        // Add fields to update
        if (!empty($klasifikacijska_oznaka->getKlasa_br())) {
          $update_array[] = "klasa_broj = '" . $db->escape($klasifikacijska_oznaka->getKlasa_br()) . "'";
        }
        if (!empty($klasifikacijska_oznaka->getSadrzaj())) {
          $update_array[] = "sadrzaj = '" . $db->escape($klasifikacijska_oznaka->getSadrzaj()) . "'";
        }
        if (!empty($klasifikacijska_oznaka->getDosjeBroj())) {
          $update_array[] = "dosje_broj = '" . $db->escape($klasifikacijska_oznaka->getDosjeBroj()) . "'";
        }
        if (!empty($klasifikacijska_oznaka->getVrijemeCuvanja())) {
          $update_array[] = "vrijeme_cuvanja = '" . $db->escape($klasifikacijska_oznaka->getVrijemeCuvanja()) . "'";
        }
        if (!empty($klasifikacijska_oznaka->getOpisKlasifikacijskeOznake())) {
          $update_array[] = "opis_klasifikacijske_oznake = '" . $db->escape($klasifikacijska_oznaka->getOpisKlasifikacijskeOznake()) . "'";
        }

        // Build WHERE clause using original combination
        $where_array[] = "klasa_broj = '$origKlasa'";
        $where_array[] = "sadrzaj = '$origSadrzaj'";
        $where_array[] = "dosje_broj = '$origDosje'";

        if (!empty($update_array)) {
          $sql = "UPDATE " . MAIN_DB_PREFIX . "a_klasifikacijska_oznaka 
                    SET " . implode(', ', $update_array) . "
                    WHERE " . implode(' AND ', $where_array);

          dol_syslog("Update SQL: $sql", LOG_DEBUG);

          if ($db->query($sql)) {
            setEventMessages($langs->trans("Uspjesno azurirana klasifikacijska oznaka"), null, 'mesgs');
          } else {
            setEventMessages($langs->trans("ErrorDatabase") . ": " . $db->lasterror(), null, 'errors');
            $error++;
          }
        } else {
          setEventMessages($langs->trans("NemaPromjenaZaSpremanje"), null, 'warnings');
        }
        unset($klasifikacijska_oznaka);
      }
    }
  }

  /***************** /***************** /***************** /*****************/
  /***************** SEKCIJA OZNAKA USTANOVE   ******************************/
  /***************** /***************** /***************** /*****************/

  // 2. Oznaka ustanove 
  if (isset($_POST['action_ustanova'])) {
    header('Content-Type: application/json; charset=UTF-8');
    ob_end_clean();

    $oznaka_ustanove = new Oznaka_ustanove();
    try {
      $conf->global->MAIN_HTML_THEME = 'nodumb';
      $db->begin();
      if ($podaci_postoje) {
        $oznaka_ustanove->setID_oznaka_ustanove($podaci_postoje->singleton);
      }
      $oznaka_ustanove->setOznaka_ustanove(GETPOST('code_ustanova', 'alphanohtml'));
      // Validacija formata unesenog teksta oznake_ustanove
      if (!preg_match('/^\d{4}-\d-\d$/', $oznaka_ustanove->getOznaka_ustanove())) {
        throw new Exception($langs->trans("Neispravan format Oznake Ustanove"));
      }

      $oznaka_ustanove->setNaziv_ustanove(GETPOST('name_ustanova', 'alphanohtml'));
      $action = GETPOST('action_ustanova', 'alpha');
      $sql = '';

      // Validacija tipke DODAJ / AZURIRAJ
      if ($action === 'add' && !$podaci_postoje) {
        dol_syslog("Dodaj Klik", LOG_INFO);
        $sql = "INSERT INTO " . MAIN_DB_PREFIX . "a_oznaka_ustanove 
                      (code_ustanova, name_ustanova) 
                      VALUES ( 
                    '" . $db->escape($oznaka_ustanove->getOznaka_ustanove()) . "',
                    '" . $db->escape($oznaka_ustanove->getNaziv_ustanove()) . "'                  
                )";
      } else {
        if (!is_object($podaci_postoje) || empty($podaci_postoje->singleton)) {
          throw new Exception($langs->trans('RecordNotFound'));
        }
        $oznaka_ustanove->setID_oznaka_ustanove($podaci_postoje->singleton);
        dol_syslog("Azuriraj Klik", LOG_INFO);
        $sql = "UPDATE " . MAIN_DB_PREFIX . "a_oznaka_ustanove 
                SET code_ustanova =  '" . $db->escape($oznaka_ustanove->getOznaka_ustanove()) . "',
                name_ustanova = '" . $db->escape($oznaka_ustanove->getNaziv_ustanove()) . "'
                WHERE ID_ustanove = '" . $db->escape($oznaka_ustanove->getID_oznaka_ustanove()) . "'";
      }

      $resql = $db->query($sql);
      if (!$resql) {
        dol_syslog("NE RADI DOBRO db->query(sql, params)", LOG_ERR);
        throw new Exception($db->lasterror());
      }

      $db->commit();

      echo json_encode([
        'success' => true,
        'message' => $langs->trans($action === 'add' ? 'Oznaka Ustanove Uspjesno dodana' : 'Oznaka Ustanove uspjesno azurirana'),
        'data' => [
          'code_ustanova' => $oznaka_ustanove->getOznaka_ustanove(),
          'name_ustanova' => $oznaka_ustanove->getNaziv_ustanove()
        ]
      ]);
      exit;
    } catch (Exception $e) {
      $db->rollback();
      http_response_code(500);
      echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
      ]);
    }
    unset($oznaka_ustanove);
    exit;
  }

  /***************** /***************** /***************** /*****************/
  /***************** SEKCIJA KLASIFIKACIJSKA OZNAKA ****************/
  /***************** /***************** /***************** /*****************/

  // 3. Unos klasifikacijske oznake
  if (isset($_POST['action_klasifikacija'])) {
    $klasifikacijska_oznaka = new Klasifikacijska_oznaka();
    $klasifikacijska_oznaka->setKlasa_br(GETPOST('klasa_br', 'int'));
    if (!preg_match('/^\d{3}$/', $klasifikacijska_oznaka->getKlasa_br())) {
      setEventMessages($langs->trans("ErrorKlasaBrFormat"), null, 'errors');
      $error++;
    }
    $klasifikacijska_oznaka->setSadrzaj(GETPOST('sadrzaj', 'int'));
    if (!preg_match('/^\d{2}$/', $klasifikacijska_oznaka->getSadrzaj()) || $klasifikacijska_oznaka->getSadrzaj() > 99 || $klasifikacijska_oznaka->getSadrzaj() < 00) {
      setEventMessages($langs->trans("ErrorSadrzajFormat"), null, 'errors');
      $error++;
    }
    $klasifikacijska_oznaka->setDosjeBroj(GETPOST('dosje_br', 'int'));
    if (!preg_match('/^\d{2}$/', $klasifikacijska_oznaka->getDosjeBroj()) || $klasifikacijska_oznaka->getDosjeBroj() > 50 || $klasifikacijska_oznaka->getDosjeBroj() < 0) {
      setEventMessages($langs->trans("ErrorDosjeBrojFormat"), null, 'errors');
      $error++;
    }
    $klasifikacijska_oznaka->setVrijemeCuvanja($klasifikacijska_oznaka->CastVrijemeCuvanjaToInt(GETPOST('vrijeme_cuvanja', 'int')));
    if (!preg_match('/^\d{1,2}$/', $klasifikacijska_oznaka->getVrijemeCuvanja()) || $klasifikacijska_oznaka->getVrijemeCuvanja() > 10 || $klasifikacijska_oznaka->getVrijemeCuvanja() < 0) {
      setEventMessages($langs->trans("ErrorVrijemeCuvanjaFormat"), null, 'errors');
      $error++;
    }  // TODO dodaj sve ErrorVrijemeCuvanjaFormat u lang file (i sve ostale tekstove koje korisimo u setEventMessages)
    $klasifikacijska_oznaka->setOpisKlasifikacijskeOznake(GETPOST('opis_klasifikacije', 'alphanohtml'));

    // Logika za gumb Unos Klasifikacijske Oznake : DODAJ
    if ($_POST['action_klasifikacija'] === 'add') {
      // provjera da li postoji vec klasa s unesenim brojem
      $klasa_br = $db->escape($klasifikacijska_oznaka->getKlasa_br());
      $sadrzaj = $db->escape($klasifikacijska_oznaka->getSadrzaj());
      $dosje_br = $db->escape($klasifikacijska_oznaka->getDosjeBroj());

      // Check if combination exists
      $sqlProvjera = "SELECT ID_klasifikacijske_oznake 
                    FROM " . MAIN_DB_PREFIX . "a_klasifikacijska_oznaka 
                    WHERE klasa_broj = '$klasa_br'
                    AND sadrzaj = '$sadrzaj'
                    AND dosje_broj = '$dosje_br'";
      $rezultatProvjere = $db->query($sqlProvjera);
      if ($db->num_rows($rezultatProvjere) > 0) {
        setEventMessages($langs->trans("KombinacijaKlaseSadrzajaDosjeaVecPostoji"), null, 'errors');
        $error++;
      } else { // ako ne postoji opleti dalje s insertom
        $sql = "INSERT INTO " . MAIN_DB_PREFIX . "a_klasifikacijska_oznaka 
                (ID_ustanove, klasa_broj, sadrzaj, dosje_broj, vrijeme_cuvanja, opis_klasifikacijske_oznake) 
                VALUES (
                    " . (int)$ID_ustanove . ",
                    '" . $db->escape($klasifikacijska_oznaka->getKlasa_br()) . "',
                    '" . $db->escape($klasifikacijska_oznaka->getSadrzaj()) . "',
                    '" . $db->escape($klasifikacijska_oznaka->getDosjeBroj()) . "',
                    '" . $db->escape($klasifikacijska_oznaka->getVrijemeCuvanja()) . "',
                    '" . $db->escape($klasifikacijska_oznaka->getOpisKlasifikacijskeOznake()) . "'
                )";
        $rezultatProvjere = $db->query($sql);
        if (!$rezultatProvjere) {
          if ($db->lasterrno() == 1062) {
            setEventMessages($langs->trans("ErrorKombinacijaDuplicate"), null, 'errors');
          } else {
            setEventMessages($langs->trans("ErrorDatabase") . ": " . $db->lasterror(), null, 'errors');
          }
          $error++;
        } else {
          setEventMessages($langs->trans("Uspjesno pohranjena klasifikacijska oznaka"), null, 'mesgs');
        }
        unset($klasifikacijska_oznaka);
      }

      // Logika za gumb Unos Klasifikacijske Oznake : AZURIRAJ
    } elseif ($_POST['action_klasifikacija'] === 'update') {
      dol_syslog("Received POST data: " . print_r($_POST, true), LOG_DEBUG);

      $id_oznake = GETPOST('id_klasifikacijske_oznake', 'int');
      dol_syslog("ID klasifikacijske oznake: " . $id_oznake, LOG_DEBUG);

      if (!$id_oznake) {
        setEventMessages($langs->trans("ErrorMissingRecordID"), null, 'errors');
        $error++;
      } else {
        // Check if the record with this ID exists
        $sqlProvjera = "SELECT * FROM " . MAIN_DB_PREFIX . "a_klasifikacijska_oznaka 
            WHERE ID_klasifikacijske_oznake = " . (int)$id_oznake;

        $rezultatProvjere = $db->query($sqlProvjera);

        if ($db->num_rows($rezultatProvjere) <= 0) {
          setEventMessages($langs->trans("KlasifikacijskaOznakaNePostoji"), null, 'errors');
          $error++;
        } else {
          $update_array = array();

          // Build the update array
          if (!empty($klasifikacijska_oznaka->getKlasa_br())) {
            $update_array[] = "klasa_broj = '" . $db->escape($klasifikacijska_oznaka->getKlasa_br()) . "'";
          }
          if (!empty($klasifikacijska_oznaka->getSadrzaj())) {
            $update_array[] = "sadrzaj = '" . $db->escape($klasifikacijska_oznaka->getSadrzaj()) . "'";
          }
          if (!empty($klasifikacijska_oznaka->getDosjeBroj())) {
            $update_array[] = "dosje_broj = '" . $db->escape($klasifikacijska_oznaka->getDosjeBroj()) . "'";
          }
          if (!empty($klasifikacijska_oznaka->getVrijemeCuvanja())) {
            $update_array[] = "vrijeme_cuvanja = '" . $db->escape($klasifikacijska_oznaka->getVrijemeCuvanja()) . "'";
          }
          if (!empty($klasifikacijska_oznaka->getOpisKlasifikacijskeOznake())) {
            $update_array[] = "opis_klasifikacijske_oznake = '" . $db->escape($klasifikacijska_oznaka->getOpisKlasifikacijskeOznake()) . "'";
          }

          if (count($update_array) > 0) {
            $sql = "UPDATE " . MAIN_DB_PREFIX . "a_klasifikacijska_oznaka 
                SET " . implode(', ', $update_array) . "
                WHERE ID_klasifikacijske_oznake = " . (int)$id_oznake;

            dol_syslog("Update SQL: $sql", LOG_DEBUG);

            if ($db->query($sql)) {
              setEventMessages($langs->trans("Uspjesno azurirana klasifikacijska oznaka"), null, 'mesgs');
            } else {
              setEventMessages($langs->trans("ErrorDatabase") . ": " . $db->lasterror(), null, 'errors');
              $error++;
            }
          } else {
            setEventMessages($langs->trans("NemaPromjenaZaSpremanje"), null, 'warnings');
          }
          unset($klasifikacijska_oznaka);
        }
      }
      // logika za gumb OBRISI
    } elseif ($_POST['action_klasifikacija'] === 'delete') {

      $id_oznake = GETPOST('id_klasifikacijske_oznake', 'int');

      if (!$id_oznake) {
        setEventMessages($langs->trans("ErrorMissingRecordID"), null, 'errors');
        $error++;
      } else {
        try {
          $db->begin();

          // First check if the record exists
          $sqlProvjera = "SELECT ID_klasifikacijske_oznake 
                            FROM " . MAIN_DB_PREFIX . "a_klasifikacijska_oznaka 
                            WHERE ID_klasifikacijske_oznake = " . (int)$id_oznake;

          $rezultatProvjere = $db->query($sqlProvjera);

          if ($db->num_rows($rezultatProvjere) <= 0) {
            setEventMessages($langs->trans("KlasifikacijskaOznakaNePostoji"), null, 'errors');
            $error++;
          } else {
            // Delete query using ID
            $sql = "DELETE FROM " . MAIN_DB_PREFIX . "a_klasifikacijska_oznaka 
                        WHERE ID_klasifikacijske_oznake = " . (int)$id_oznake;

            if ($db->query($sql)) {
              $db->commit();
              setEventMessages($langs->trans("KlasifikacijskaOznakaUspjesnoObrisana"), null, 'mesgs');

              // Redirect da se izbjegne ponovno slanje forme
              header('Location: ' . $_SERVER['PHP_SELF']);
              exit;

            } else {
              $db->rollback();
              setEventMessages($langs->trans("ErrorDeleteFailed") . ": " . $db->lasterror(), null, 'errors');
            }
          }
        } catch (Exception $e) {
          $db->rollback();
          setEventMessages($langs->trans("ErrorException") . ": " . $e->getMessage(), null, 'errors');
        }
      }
    }
  }
}

// Main hero section with modern design
print '<main class="seup-settings-hero">';

// Floating background elements
print '<div class="seup-floating-elements">';
for ($i = 1; $i <= 5; $i++) {
    print '<div class="seup-floating-element"></div>';
}
print '</div>';

print '<div class="seup-settings-content">';

// Header section
print '<div class="seup-settings-header">';
print '<h1 class="seup-settings-title">Postavke Sustava</h1>';
print '<p class="seup-settings-subtitle">Konfigurirajte osnovne parametre, korisničke oznake i klasifikacijski sustav</p>';
print '</div>';

// Settings grid
print '<div class="seup-settings-grid">';

// Card 1: Klasifikacijske oznake (wide card at top)
print '<div class="seup-settings-card seup-card-wide animate-fade-in-up">';
print '<div class="seup-card-header">';
print '<div class="seup-card-icon"><i class="fas fa-sitemap"></i></div>';
print '<h3 class="seup-card-title">Klasifikacijske Oznake</h3>';
print '<p class="seup-card-description">Upravljanje hijerarhijskim sustavom klasifikacije dokumenata i predmeta</p>';
print '</div>';
print '<form method="post" action="' . $_SERVER['PHP_SELF'] . '" class="seup-form">';
print '<input type="hidden" id="hidden_id_klasifikacijske_oznake" name="id_klasifikacijske_oznake" value="">';

print '<div class="seup-form-grid seup-grid-3">';
print '<div class="seup-form-group seup-autocomplete-container">';
print '<label for="klasa_br" class="seup-label"><i class="fas fa-layer-group me-2"></i>Klasa broj (000)</label>';
print '<input type="text" id="klasa_br" name="klasa_br" class="seup-input" ';
print 'pattern="\d{3}" maxlength="3" placeholder="000" autocomplete="off">';
print '<div id="autocomplete-results" class="seup-autocomplete-dropdown"></div>';
print '</div>';

print '<div class="seup-form-group">';
print '<label for="sadrzaj" class="seup-label"><i class="fas fa-list me-2"></i>Sadržaj (00)</label>';
print '<input type="text" id="sadrzaj" name="sadrzaj" class="seup-input" ';
print 'pattern="\d{2}" maxlength="2" placeholder="00">';
print '</div>';

print '<div class="seup-form-group">';
print '<label for="dosje_br" class="seup-label"><i class="fas fa-folder me-2"></i>Dosje broj</label>';
print '<select id="dosje_br" name="dosje_br" class="seup-select" required>';
print '<option value="">Odaberite dosje</option>';
for ($i = 1; $i <= 50; $i++) {
    $val = sprintf('%02d', $i);
    print '<option value="' . $val . '">' . $val . '</option>';
}
print '</select>';
print '</div>';
print '</div>';

print '<div class="seup-form-grid">';
print '<div class="seup-form-group">';
print '<label for="vrijeme_cuvanja" class="seup-label"><i class="fas fa-clock me-2"></i>Vrijeme čuvanja</label>';
print '<select id="vrijeme_cuvanja" name="vrijeme_cuvanja" class="seup-select" required>';
print '<option value="permanent">Trajno</option>';
for ($g = 1; $g <= 10; $g++) {
    print '<option value="' . $g . '">' . $g . ' godina</option>';
}
print '</select>';
print '</div>';
print '<div class="seup-form-group">';
print '<label for="opis_klasifikacije" class="seup-label"><i class="fas fa-align-left me-2"></i>Opis klasifikacije</label>';
print '<textarea id="opis_klasifikacije" name="opis_klasifikacije" class="seup-textarea" ';
print 'rows="3" placeholder="Unesite detaljni opis klasifikacijske oznake"></textarea>';
print '</div>';
print '</div>';

print '<div class="seup-form-actions">';
print '<button type="submit" name="action_klasifikacija" value="add" class="seup-btn seup-btn-primary">';
print '<i class="fas fa-plus me-2"></i>Dodaj';
print '</button>';
print '<button type="submit" name="action_klasifikacija" value="update" class="seup-btn seup-btn-secondary">';
print '<i class="fas fa-edit me-2"></i>Ažuriraj';
print '</button>';
print '<button type="submit" name="action_klasifikacija" value="delete" class="seup-btn seup-btn-danger">';
print '<i class="fas fa-trash me-2"></i>Obriši';
print '</button>';
print '</div>';
print '</form>';
print '</div>';

// Card 2: Interne oznake korisnika
print '<div class="seup-settings-card animate-fade-in-up">';
print '<div class="seup-card-header">';
print '<div class="seup-card-icon"><i class="fas fa-users"></i></div>';
print '<h3 class="seup-card-title">Interne Oznake Korisnika</h3>';
print '<p class="seup-card-description">Upravljanje korisničkim oznakama i radnim mjestima</p>';
print '</div>';
print '<form method="post" action="' . $_SERVER['PHP_SELF'] . '" class="seup-form">';
print '<div class="seup-form-grid">';
print '<div class="seup-form-group">';
print '<label for="ime_user" class="seup-label"><i class="fas fa-user me-2"></i>Korisnik</label>';
print '<select name="ime_user" id="ime_user" class="seup-select" required>';
print '<option value="">Odaberite korisnika</option>';
foreach ($listUsers as $u) {
    print '<option value="' . htmlspecialchars($u->getFullName($langs)) . '">';
    print htmlspecialchars($u->getFullName($langs));
    print '</option>';
}
print '</select>';
print '</div>';
print '<div class="seup-form-group">';
print '<label for="redni_broj" class="seup-label"><i class="fas fa-hashtag me-2"></i>Redni broj (0-99)</label>';
print '<input type="number" name="redni_broj" id="redni_broj" class="seup-input" min="0" max="99" required>';
print '</div>';
print '</div>';
print '<div class="seup-form-group">';
print '<label for="radno_mjesto_korisnika" class="seup-label"><i class="fas fa-briefcase me-2"></i>Radno mjesto</label>';
print '<input type="text" name="radno_mjesto_korisnika" id="radno_mjesto_korisnika" class="seup-input" required>';
print '</div>';
print '<div class="seup-form-actions">';
print '<button type="submit" name="action_oznaka" value="add" class="seup-btn seup-btn-primary">';
print '<i class="fas fa-plus me-2"></i>Dodaj';
print '</button>';
print '<button type="submit" name="action_oznaka" value="update" class="seup-btn seup-btn-secondary">';
print '<i class="fas fa-edit me-2"></i>Ažuriraj';
print '</button>';
print '<button type="submit" name="action_oznaka" value="delete" class="seup-btn seup-btn-danger">';
print '<i class="fas fa-trash me-2"></i>Obriši';
print '</button>';
print '</div>';
print '</form>';
print '</div>';

// Card 3: Oznaka ustanove
print '<div class="seup-settings-card animate-fade-in-up">';
print '<div class="seup-card-header">';
print '<div class="seup-card-icon"><i class="fas fa-building"></i></div>';
print '<h3 class="seup-card-title">Oznaka Ustanove</h3>';
print '<p class="seup-card-description">Osnovni podaci o ustanovi i njena identifikacijska oznaka</p>';
print '</div>';
print '<form method="post" action="' . $_SERVER['PHP_SELF'] . '" id="ustanova-form" class="seup-form">';
print '<input type="hidden" name="action_ustanova" id="form-action" value="' . ($podaci_postoje ? 'update' : 'add') . '">';
print '<div id="messageDiv" class="seup-alert d-none" role="alert"></div>';
print '<div class="seup-form-grid">';
print '<div class="seup-form-group">';
print '<label for="code_ustanova" class="seup-label"><i class="fas fa-code me-2"></i>Oznaka (format: 0000-0-0)</label>';
print '<input type="text" id="code_ustanova" name="code_ustanova" class="seup-input" ';
print 'pattern="^\d{4}-\d-\d$" placeholder="0000-0-0" required ';
print 'value="' . ($podaci_postoje ? htmlspecialchars($podaci_postoje->code_ustanova) : '') . '">';
print '</div>';
print '<div class="seup-form-group">';
print '<label for="name_ustanova" class="seup-label"><i class="fas fa-tag me-2"></i>Naziv ustanove</label>';
print '<input type="text" id="name_ustanova" name="name_ustanova" class="seup-input" ';
print 'placeholder="Unesite naziv ustanove" required ';
print 'value="' . ($podaci_postoje ? htmlspecialchars($podaci_postoje->name_ustanova) : '') . '">';
print '</div>';
print '</div>';
print '<div class="seup-form-actions">';
print '<button type="submit" id="ustanova-submit" class="seup-btn seup-btn-primary">';
print '<i class="fas fa-' . ($podaci_postoje ? 'edit' : 'plus') . ' me-2"></i>';
print ($podaci_postoje ? 'Ažuriraj' : 'Dodaj');
print '</button>';
print '</div>';
print '</form>';
print '</div>';

print '</div>'; // seup-settings-grid

print '</div>'; // seup-settings-content

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

print '</main>';

// JavaScript for enhanced functionality
print '<script src="/custom/seup/js/seup-modern.js"></script>';

?>

<script>
document.addEventListener('DOMContentLoaded', function() {
    // Enhanced form handling for ustanova
    const form = document.getElementById('ustanova-form');
    const actionField = document.getElementById('form-action');
    const btnSubmit = document.getElementById('ustanova-submit');

    if (form && btnSubmit) {
        form.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            // Add loading state
            btnSubmit.classList.add('seup-loading');
            btnSubmit.disabled = true;
            
            const formData = new FormData(this);
            formData.append('action_ustanova', btnSubmit.textContent.trim() === 'Dodaj' ? 'add' : 'update');

            try {
                const response = await fetch('<?php echo $_SERVER['PHP_SELF'] ?>', {
                    method: 'POST',
                    body: formData,
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest',
                        'Accept': 'application/json'
                    }
                });

                if (!response.ok) {
                    const text = await response.text();
                    throw new Error(`HTTP error ${response.status}: ${text.slice(0, 100)}`);
                }

                const contentType = response.headers.get('content-type');
                if (!contentType || !contentType.includes('application/json')) {
                    const text = await response.text();
                    throw new Error(`Invalid response: ${text.slice(0, 100)}`);
                }

                const result = await response.json();
                
                if (result.success) {
                    // Update UI
                    actionField.value = 'update';
                    btnSubmit.innerHTML = '<i class="fas fa-edit me-2"></i>Ažuriraj';
                    btnSubmit.classList.remove('seup-btn-primary');
                    btnSubmit.classList.add('seup-btn-secondary');

                    // Update input values
                    document.getElementById('code_ustanova').value = result.data.code_ustanova;
                    document.getElementById('name_ustanova').value = result.data.name_ustanova;

                    // Show success message
                    showMessage(result.message, 'success');
                } else {
                    showMessage(result.error || 'Greška pri spremanju', 'error');
                }
            } catch (error) {
                console.error('Error:', error);
                showMessage('Došlo je do greške: ' + error.message, 'error');
            } finally {
                // Remove loading state
                btnSubmit.classList.remove('seup-loading');
                btnSubmit.disabled = false;
            }
        });
    }

    // Enhanced autocomplete for klasifikacijske oznake
    const input = document.getElementById('klasa_br');
    const resultsContainer = document.getElementById('autocomplete-results');
    const formFields = {
        sadrzaj: document.getElementById('sadrzaj'),
        dosje_br: document.getElementById('dosje_br'),
        vrijeme_cuvanja: document.getElementById('vrijeme_cuvanja'),
        opis_klasifikacije: document.getElementById('opis_klasifikacije')
    };

    if (input && resultsContainer) {
        input.addEventListener('input', debounce(function(e) {
            const searchTerm = e.target.value.trim();
            if (searchTerm.length >= 1) {
                fetch('../class/autocomplete.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    body: 'query=' + encodeURIComponent(searchTerm)
                })
                .then(response => {
                    if (!response.ok) throw new Error(response.statusText);
                    return response.json();
                })
                .then(data => showResults(data))
                .catch(error => {
                    console.error('Autocomplete error:', error);
                    clearResults();
                });
            } else {
                clearResults();
            }
        }, 300));

        function showResults(results) {
            resultsContainer.innerHTML = '';
            resultsContainer.style.display = 'block';
            
            if (results.length === 0) {
                const div = document.createElement('div');
                div.className = 'seup-autocomplete-item';
                div.innerHTML = '<div class="seup-autocomplete-main">Nema rezultata</div>';
                resultsContainer.appendChild(div);
                return;
            }

            results.forEach(result => {
                const div = document.createElement('div');
                div.className = 'seup-autocomplete-item';
                div.innerHTML = `
                    <div class="seup-autocomplete-main">${result.klasa_br}-${result.sadrzaj}/${result.dosje_br}</div>
                    <div class="seup-autocomplete-desc">${result.opis_klasifikacije || 'Nema opisa'}</div>
                `;
                div.dataset.id = result.ID;
                div.dataset.record = JSON.stringify(result);
                div.addEventListener('click', () => populateForm(result));
                resultsContainer.appendChild(div);
            });
        }

        function populateForm(data) {
            input.value = data.klasa_br;
            formFields.sadrzaj.value = data.sadrzaj || '';
            formFields.dosje_br.value = data.dosje_br || '';
            formFields.vrijeme_cuvanja.value = data.vrijeme_cuvanja.toString() === '0' ? 'permanent' : data.vrijeme_cuvanja;
            formFields.opis_klasifikacije.value = data.opis_klasifikacije || '';
            
            document.getElementById('hidden_id_klasifikacijske_oznake').value = data.ID;
            clearResults();
            
            // Visual feedback
            input.style.borderColor = 'var(--success-500)';
            setTimeout(() => {
                input.style.borderColor = '';
            }, 2000);
        }

        function clearResults() {
            resultsContainer.innerHTML = '';
            resultsContainer.style.display = 'none';
        }

        // Hide results when clicking outside
        document.addEventListener('click', function(e) {
            if (!e.target.closest('.seup-autocomplete-container')) {
                clearResults();
            }
        });
    }

    function debounce(func, wait) {
        let timeout;
        return function(...args) {
            clearTimeout(timeout);
            timeout = setTimeout(() => func.apply(this, args), wait);
        };
    }

    // Enhanced message display
    window.showMessage = function(message, type = 'success', duration = 5000) {
        // Create or update message element
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
});
</script>

<style>
/* Toast messages */
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

/* Loading state for buttons */
.seup-btn.seup-loading {
    position: relative;
    color: transparent;
}

.seup-btn.seup-loading::after {
    content: '';
    position: absolute;
    top: 50%;
    left: 50%;
    width: 16px;
    height: 16px;
    margin: -8px 0 0 -8px;
    border: 2px solid transparent;
    border-top: 2px solid currentColor;
    border-radius: 50%;
    animation: spin 1s linear infinite;
}

@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}

/* Enhanced autocomplete */
.seup-autocomplete-dropdown {
    display: none;
}

.seup-autocomplete-dropdown.show {
    display: block;
}
</style>

<?php
llxFooter();
$db->close();
?>