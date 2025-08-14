<?php
/**
 * OnlyOffice Editor integracija za Dolibarr ECM
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);

// Učitaj Dolibarr
$res = 0;
if (!$res && !empty($_SERVER["CONTEXT_DOCUMENT_ROOT"])) {
    $res = @include $_SERVER["CONTEXT_DOCUMENT_ROOT"] . "/main.inc.php";
}

$tmp = empty($_SERVER['SCRIPT_FILENAME']) ? '' : $_SERVER['SCRIPT_FILENAME']; 
$tmp2 = realpath(__FILE__); 
$i = strlen($tmp) - 1; 
$j = strlen($tmp2) - 1;
while ($i > 0 && $j > 0 && isset($tmp[$i]) && isset($tmp2[$j]) && $tmp[$i] == $tmp2[$j]) {
    $i--; $j--;
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
    die("Učitavanje glavnog dijela nije uspjelo");
}

// Inicijalizacija Dolibarr okruženja
require_once DOL_DOCUMENT_ROOT . '/core/class/html.formfile.class.php';
require_once DOL_DOCUMENT_ROOT . '/ecm/class/ecmdirectory.class.php';
require_once DOL_DOCUMENT_ROOT . '/ecm/class/ecmfiles.class.php';

// POSTAVI $langs PRIJE KORIŠTENJA
global $langs;
if (!is_object($langs)) {
    require_once DOL_DOCUMENT_ROOT . '/core/class/translate.class.php';
    $langs = new Translate('', $conf);
    $langs->setDefaultLang('auto');
}

// Sada je sigurno učitano
$langs->loadLangs(array("ecm@ecm"));

// Konfiguracija OnlyOffice
define('ONLYOFFICE_SERVER', 'https://office.8core.org');
define('JWT_SECRET_OUTBOUND', '0y4Og2DmhaHaCEGKmuVwjqwMt7B90DAL');
define('JWT_HEADER', 'AuthorizationJwt');

// GET parametri
$ecmfile_id = GETPOST('ecmfile_id', 'int');
$action = GETPOST('action', 'alpha');

// Inicijalizacija objekata
global $db;
$form = new Form($db);
$formfile = new FormFile($db);
$ecmdir = new EcmDirectory($db);
$ecmfile = new EcmFiles($db);

// Funkcija za generiranje JWT tokena
function generateJWT($payload, $secret) {
    $header = json_encode(['typ' => 'JWT', 'alg' => 'HS256']);
    $base64UrlHeader = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
    $base64UrlPayload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode(json_encode($payload)));
    $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, $secret, true);
    $base64UrlSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));
    return $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;
}

// Funkcija za određivanje vrste dokumenta
function getDocumentType($filename) {
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $text = ['doc', 'docx', 'odt', 'rtf', 'txt'];
    $spreadsheet = ['xls', 'xlsx', 'ods', 'csv'];
    $presentation = ['ppt', 'pptx', 'odp'];
    
    if (in_array($ext, $text)) return 'text';
    if (in_array($ext, $spreadsheet)) return 'spreadsheet';
    if (in_array($ext, $presentation)) return 'presentation';
    return 'text';
}

llxHeader('', 'OnlyOffice Editor', '');

// Dummy lista dokumenata
$documents = [
    ['id' => 101, 'name' => 'Test dokument 1.docx', 'mimetype' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
    ['id' => 102, 'name' => 'Prezentacija 2025.pptx', 'mimetype' => 'application/vnd.openxmlformats-officedocument.presentationml.presentation'],
    ['id' => 103, 'name' => 'Proračunska tablica.xlsx', 'mimetype' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
];

// AJAX endpoint za dobivanje JWT tokena
if ($action == 'get_jwt_token' && $ecmfile_id) {
    $doc = null;
    foreach ($documents as $d) {
        if ($d['id'] == $ecmfile_id) {
            $doc = $d;
            break;
        }
    }
    
    if ($doc) {
        $payload = [
            'document_id' => $ecmfile_id,
            'user_id' => $user->id,
            'permissions' => 'edit',
            'exp' => time() + 3600
        ];
        
        $jwt = generateJWT($payload, JWT_SECRET_OUTBOUND);
        
        header('Content-Type: application/json');
        echo json_encode([
            'success' => true,
            'token' => $jwt,
            'document' => [
                'name' => $doc['name'],
                'type' => getDocumentType($doc['name'])
            ]
        ]);
        exit;
    }
}

// --- POČETAK HTML DIZAJNA ---
print <<<HTML
<div class="onlyoffice-container">
  <div class="onlyoffice-header">
    <h1><i class="fa fa-file-text-o"></i> SEUP Dokument editor</h1>
  </div>
  
  <div class="sort-controls">
    <h2><i class="fa fa-sort"></i> {$langs->trans("Klasificiraj po:")}</h2>
    <form method="get" action="{$_SERVER['PHP_SELF']}">
      <select name="sort" id="sort" onchange="this.form.submit()">
        <option value="id">{$langs->trans("ID")}</option>
        <option value="name">{$langs->trans("Name")}</option>
        <option value="mimetype">{$langs->trans("DocumentType")}</option>
      </select>
    </form>
  </div>
  
  <div class="documents-list">
    <h2><i class="fa fa-files-o"></i> {$langs->trans("Dostupni dokumenti")}</h2>
    
    <div class="document-grid">
HTML;

// Prikaz dokumenata
foreach ($documents as $doc) {
    $icon = 'fa-file-text-o';
    if (strpos($doc['mimetype'], 'spreadsheet') !== false) $icon = 'fa-file-excel-o';
    if (strpos($doc['mimetype'], 'presentation') !== false) $icon = 'fa-file-powerpoint-o';
    
    print <<<HTML
      <div class="document-card">
        <div class="doc-icon">
          <i class="fa {$icon}"></i>
        </div>
        <div class="doc-details">
          <h3>{$doc['name']}</h3>
          <p class="doc-type">{$doc['mimetype']}</p>
        </div>
        <div class="doc-actions">
          <button class="edit-btn" data-id="{$doc['id']}">
            <i class="fa fa-pencil"></i> {$langs->trans("Edit")}
          </button>
        </div>
      </div>
HTML;
}

print <<<HTML
    </div>
  </div>
</div>

<!-- OnlyOffice Editor Modal -->
<div id="onlyofficeModal" class="onlyoffice-modal">
  <div class="modal-content">
    <div class="modal-header">
      <h2 id="modalTitle"><i class="fa fa-spinner fa-spin"></i> {$langs->trans("LoadingDocument")}</h2>
      <button class="close-btn">&times;</button>
    </div>
    <div class="modal-body">
      <iframe id="onlyofficeFrame"></iframe>
    </div>
    <div class="modal-footer">
      <button id="btnSave" class="save-btn">
        <i class="fa fa-save"></i> {$langs->trans("Save")}
      </button>
      <button id="btnFullscreen" class="fullscreen-btn">
        <i class="fa fa-expand"></i> {$langs->trans("Fullscreen")}
      </button>
      <button class="close-btn">
        <i class="fa fa-times"></i> {$langs->trans("Close")}
      </button>
    </div>
  </div>
</div>

<style>
/* Reset i osnovni stilovi */
* {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

body {
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
  background-color: #f5f7fa;
  color: #333;
  line-height: 1.6;
  padding: 20px;
}

.onlyoffice-container {
  max-width: 1200px;
  margin: 0 auto;
  background: white;
  border-radius: 10px;
  box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
  overflow: hidden;
}

.onlyoffice-header {
  background: linear-gradient(135deg, #1e5799, #207cca);
  color: white;
  padding: 25px 30px;
  text-align: center;
}

.onlyoffice-header h1 {
  font-size: 28px;
}

.onlyoffice-header .fa {
  margin-right: 10px;
}

.sort-controls {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 20px 30px;
  background: #f8f9fa;
  border-bottom: 1px solid #eaeaea;
}

.sort-controls h2 {
  font-size: 20px;
  color: #444;
}

.sort-controls select {
  padding: 10px 15px;
  border: 1px solid #ddd;
  border-radius: 5px;
  font-size: 16px;
  background: white;
  min-width: 200px;
}

.documents-list {
  padding: 20px 30px;
}

.documents-list h2 {
  margin-bottom: 20px;
  color: #444;
  font-size: 22px;
}

.document-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 20px;
}

.document-card {
  background: white;
  border: 1px solid #eaeaea;
  border-radius: 8px;
  padding: 20px;
  display: flex;
  flex-direction: column;
  transition: all 0.3s ease;
  box-shadow: 0 3px 10px rgba(0, 0, 0, 0.05);
}

.document-card:hover {
  transform: translateY(-5px);
  box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
  border-color: #cce5ff;
}

.doc-icon {
  text-align: center;
  margin-bottom: 15px;
}

.doc-icon .fa {
  font-size: 48px;
  color: #1e5799;
}

.doc-details h3 {
  font-size: 18px;
  margin-bottom: 8px;
  color: #1e5799;
}

.doc-type {
  color: #666;
  font-size: 14px;
}

.doc-actions {
  margin-top: auto;
  padding-top: 15px;
}

.edit-btn {
  width: 100%;
  padding: 10px;
  background: #1e5799;
  color: white;
  border: none;
  border-radius: 5px;
  cursor: pointer;
  font-size: 16px;
  transition: background 0.3s;
}

.edit-btn:hover {
  background: #15427a;
}

.edit-btn .fa {
  margin-right: 8px;
}

/* Modal stilovi */
.onlyoffice-modal {
  display: none;
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(0, 0, 0, 0.7);
  z-index: 1000;
  justify-content: center;
  align-items: center;
}

.modal-content {
  width: 90%;
  height: 90%;
  background: white;
  border-radius: 10px;
  display: flex;
  flex-direction: column;
  box-shadow: 0 0 30px rgba(0, 0, 0, 0.3);
}

.modal-header, .modal-footer {
  padding: 15px 20px;
  background: #1e5799;
  color: white;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-top-left-radius: 10px;
  border-top-right-radius: 10px;
}

.modal-header h2 {
  font-size: 20px;
}

.close-btn {
  background: none;
  border: none;
  color: white;
  font-size: 24px;
  cursor: pointer;
  padding: 5px;
}

.modal-body {
  flex: 1;
  padding: 0;
}

#onlyofficeFrame {
  width: 100%;
  height: 100%;
  border: none;
}

.modal-footer {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
  border-bottom-left-radius: 10px;
  border-bottom-right-radius: 10px;
}

.save-btn, .fullscreen-btn, .close-btn {
  padding: 8px 15px;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 14px;
  display: flex;
  align-items: center;
}

.save-btn {
  background: #28a745;
  color: white;
}

.save-btn:hover {
  background: #218838;
}

.fullscreen-btn {
  background: #6c757d;
  color: white;
}

.fullscreen-btn:hover {
  background: #5a6268;
}

.close-btn {
  background: #dc3545;
  color: white;
}

.close-btn:hover {
  background: #c82333;
}

.modal-footer .fa {
  margin-right: 5px;
}
</style>

<script>
// Funkcija za otvaranje modala
function openEditorModal(docId) {
  const modal = document.getElementById('onlyofficeModal');
  const iframe = document.getElementById('onlyofficeFrame');
  const modalTitle = document.getElementById('modalTitle');
  
  // Prikaži modal
  modal.style.display = 'flex';
  
  // Prikaži loading indikator
  iframe.src = 'about:blank';
  modalTitle.innerHTML = '<i class="fa fa-spinner fa-spin"></i> {$langs->trans("LoadingDocument")}';
  
  // Dohvati JWT token putem AJAX-a
  const xhr = new XMLHttpRequest();
  xhr.open('GET', '{$_SERVER['PHP_SELF']}?action=get_jwt_token&ecmfile_id=' + docId, true);
  xhr.setRequestHeader('Content-Type', 'application/json');
  
  xhr.onload = function() {
    if (xhr.status === 200) {
      const response = JSON.parse(xhr.responseText);
      
      if (response.success) {
        // Stvori OnlyOffice API skriptu
        const script = document.createElement('script');
        script.src = '${ONLYOFFICE_SERVER}/web-apps/apps/api/documents/api.js';
        document.head.appendChild(script);
        
        script.onload = function() {
          // Konfiguracija za OnlyOffice
          const config = {
            document: {
              fileType: response.document.type,
              key: "doc_" + docId + "_" + new Date().getTime(),
              title: response.document.name,
              url: "https://dummy-url.com/document?doc_id=" + docId,
            },
            documentType: response.document.type,
            editorConfig: {
              callbackUrl: "https://dummy-url.com/callback?doc_id=" + docId,
              user: {
                id: "{$user->id}",
                name: "{$user->firstname} {$user->lastname}"
              }
            },
            token: response.token,
            height: "100%",
            width: "100%"
          };
          
          // Inicijalizacija editora
          new DocsAPI.DocEditor("onlyofficeFrame", config);
          
          // Postavi naslov
          modalTitle.innerHTML = '<i class="fa fa-edit"></i> ' + response.document.name;
        };
      } else {
        alert("{$langs->trans("ErrorLoadingDocument")}");
        closeModal();
      }
    } else {
      alert("{$langs->trans("ServerCommunicationError")}");
      closeModal();
    }
  };
  
  xhr.send();
}

// Funkcija za zatvaranje modala
function closeModal() {
  document.getElementById('onlyofficeModal').style.display = 'none';
}

// Funkcija za puni zaslon
function toggleFullscreen() {
  const iframe = document.getElementById('onlyofficeFrame');
  
  if (!document.fullscreenElement) {
    if (iframe.requestFullscreen) {
      iframe.requestFullscreen();
    } else if (iframe.mozRequestFullScreen) {
      iframe.mozRequestFullScreen();
    } else if (iframe.webkitRequestFullscreen) {
      iframe.webkitRequestFullscreen();
    } else if (iframe.msRequestFullscreen) {
      iframe.msRequestFullscreen();
    }
  } else {
    if (document.exitFullscreen) {
      document.exitFullscreen();
    }
  }
}

// Spremi dokument
function saveDocument() {
  const iframe = document.getElementById('onlyofficeFrame');
  if (iframe.contentWindow && iframe.contentWindow.docEditor) {
    iframe.contentWindow.docEditor.downloadAs();
    alert("{$langs->trans("DocumentSaved")}");
  } else {
    alert("{$langs->trans("EditorNotReady")}");
  }
}

// Event listeneri nakon učitavanja stranice
document.addEventListener('DOMContentLoaded', function() {
  // Otvaranje editora
  document.querySelectorAll('.edit-btn').forEach(button => {
    button.addEventListener('click', function() {
      openEditorModal(this.dataset.id);
    });
  });
  
  // Zatvaranje modala
  document.querySelectorAll('.close-btn').forEach(button => {
    button.addEventListener('click', closeModal);
  });
  
  // Puni zaslon
  document.getElementById('btnFullscreen').addEventListener('click', toggleFullscreen);
  
  // Spremi dokument
  document.getElementById('btnSave').addEventListener('click', saveDocument);
  
  // Zatvori modal klikom izvan sadržaja
  document.getElementById('onlyofficeModal').addEventListener('click', function(e) {
    if (e.target === this) closeModal();
  });
});
</script>
HTML;

llxFooter();
$db->close();