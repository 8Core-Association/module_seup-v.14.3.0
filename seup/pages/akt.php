<?php
/**
 * Plaćena licenca
 * (c) 2025 8Core Association
 * Tomislav Galić <tomislav@8core.hr>
 * Marko Šimunović <marko@8core.hr>
 * Web: https://8core.hr | info@8core.hr
 * Sva prava pridržana.
 */

// Onemogući CSRF za ovu stranicu
if (!defined('NOCSRFCHECK')) define('NOCSRFCHECK', 1);

// Učitaj Dolibarr
require_once __DIR__ . '/../../main.inc.php';
// Učitaj prijevode
$langs->loadLangs(['seup@seup']);

// Priprema OnlyOffice postavki
$onlyOfficeServer = 'https://srv2.8core.org/welcome';
$onlyOfficeSecret = 'xdaIZShZqqi0vZp3M3A3458Pvi11PQy8';

// Dohvat ID dokumenta iz GET parametra
$docRowId = GETPOST('docid','int');
if (!$docRowId) $docRowId = 0;
// URL za download
$documentUrl = dol_buildpath("document.php?modulepart=file&action=download&fk={$docRowId}",1);
$documentKey = $docRowId . '-' . time();
$documentTitle = 'Dokument ' . $docRowId;

// Konfiguracija OnlyOffice
$onlyOfficeConfig = [
    'document' => [
        'fileType' => pathinfo(parse_url($documentUrl,PHP_URL_PATH), PATHINFO_EXTENSION),
        'key'      => $documentKey,
        'title'    => $documentTitle,
        'url'      => $documentUrl
    ],
    'editorConfig' => [
        'callbackUrl'=> dol_buildpath('custom/seup/onlyoffice_callback.php',1),
        'mode'       => 'edit',
        'lang'       => $langs->getDefaultLang(),
        'token'      => $onlyOfficeSecret
    ],
    'token' => $onlyOfficeSecret
];

// Prikaz headera
llxHeader('', $langs->trans('NovaStranica'));
?>

<div class="container py-5">
  <div class="row g-4 mb-4">
    <!-- Prvi stupac: OnlyOffice editor -->
    <div class="col-12 col-md-6">
      <div class="custom-container bg-white shadow rounded-3 p-4">
        <h5 class="mb-3"><?php echo $langs->trans('Kontejner1Naslov'); ?></h5>
        <p class="mb-3"><?php echo $langs->trans('Kontejner1Sadrzaj'); ?></p>
        <script src="<?php echo $onlyOfficeServer; ?>/web-apps/apps/api/documents/api.js"></script>
        <div id="onlyoffice-editor" style="width:100%; height:600px;"></div>
        <script>
          var config = <?php echo json_encode($onlyOfficeConfig); ?>;
          new DocsAPI.DocEditor('onlyoffice-editor', Object.assign({
            width: '100%', height: '600px'
          }, config));
        </script>
      </div>
    </div>

    <!-- Drugi stupac -->
    <div class="col-12 col-md-6">
      <div class="custom-container bg-white shadow rounded-3 p-4">
        <h5 class="mb-3"><?php echo $langs->trans('Kontejner2Naslov'); ?></h5>
        <p class="mb-0"><?php echo $langs->trans('Kontejner2Sadrzaj'); ?></p>
      </div>
    </div>
  </div>

  <!-- Full-width red -->
  <div class="row">
    <div class="col-12">
      <div class="custom-container bg-light shadow rounded-3 p-4">
        <h5 class="text-center mb-3"><?php echo $langs->trans('FullWidthNaslov'); ?></h5>
        <p class="text-center mb-0"><?php echo $langs->trans('FullWidthSadrzaj'); ?></p>
      </div>
    </div>
  </div>
</div>

<?php
// Footer & JS
print '<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.5/dist/js/bootstrap.bundle.min.js"></script>';
llxFooter();
$db->close();
?>
