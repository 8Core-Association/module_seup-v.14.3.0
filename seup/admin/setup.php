<?php
/* Copyright (C) 2004-2017  Laurent Destailleur     <eldy@users.sourceforge.net>
 * Copyright (C) 2024       Frédéric France         <frederic.france@free.fr>
 * Copyright (C) 2025		SuperAdmin
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * \file    seup/admin/setup.php
 * \ingroup seup
 * \brief   SEUP setup page.
 */

// Load Dolibarr environment
$res = 0;
// Try main.inc.php into web root known defined into CONTEXT_DOCUMENT_ROOT (not always defined)
if (!$res && !empty($_SERVER["CONTEXT_DOCUMENT_ROOT"])) {
	$res = @include $_SERVER["CONTEXT_DOCUMENT_ROOT"]."/main.inc.php";
}
// Try main.inc.php into web root detected using web root calculated from SCRIPT_FILENAME
$tmp = empty($_SERVER['SCRIPT_FILENAME']) ? '' : $_SERVER['SCRIPT_FILENAME'];
$tmp2 = realpath(__FILE__);
$i = strlen($tmp) - 1;
$j = strlen($tmp2) - 1;
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
// Try main.inc.php using relative path
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
require_once DOL_DOCUMENT_ROOT."/core/lib/admin.lib.php";
require_once '../lib/seup.lib.php';
//require_once "../class/myclass.class.php";

/**
 * @var Conf $conf
 * @var DoliDB $db
 * @var HookManager $hookmanager
 * @var Translate $langs
 * @var User $user
 */

// Translations
$langs->loadLangs(array("admin", "seup@seup"));

// Initialize a technical object to manage hooks of page. Note that conf->hooks_modules contains an array of hook context
/** @var HookManager $hookmanager */
$hookmanager->initHooks(array('seupsetup', 'globalsetup'));

// Parameters
$action = GETPOST('action', 'aZ09');
$backtopage = GETPOST('backtopage', 'alpha');
$modulepart = GETPOST('modulepart', 'aZ09');	// Used by actions_setmoduleoptions.inc.php

$value = GETPOST('value', 'alpha');
$label = GETPOST('label', 'alpha');
$scandir = GETPOST('scan_dir', 'alpha');
$type = 'myobject';

$error = 0;
$setupnotempty = 0;

// Access control
if (!$user->admin) {
	accessforbidden();
}


// Set this to 1 to use the factory to manage constants. Warning, the generated module will be compatible with version v15+ only
$useFormSetup = 1;

if (!class_exists('FormSetup')) {
	require_once DOL_DOCUMENT_ROOT.'/core/class/html.formsetup.class.php';
}
$formSetup = new FormSetup($db);

// Access control
if (!$user->admin) {
	accessforbidden();
}


// Enter here all parameters in your setup page

// Nextcloud configuration
$item = $formSetup->newItem('NEXTCLOUD_URL');
$item->defaultFieldValue = 'https://your-nextcloud.com';
$item->fieldAttr['placeholder'] = 'https://cloud.example.com';
$item->cssClass = 'minwidth500';

$item = $formSetup->newItem('NEXTCLOUD_USERNAME');
$item->fieldAttr['placeholder'] = 'nextcloud-username';
$item->cssClass = 'minwidth300';

$item = $formSetup->newItem('NEXTCLOUD_PASSWORD');
$item->fieldAttr['placeholder'] = 'app-password-or-token';
$item->fieldAttr['type'] = 'password';
$item->cssClass = 'minwidth300';

// Nextcloud Enable/Disable
$formSetup->newItem('NEXTCLOUD_ENABLED')->setAsYesNo();

// ECM Nextcloud Mount detection
$item = $formSetup->newItem('ECM_IS_NEXTCLOUD_MOUNT');
$item->setAsYesNo();
$item->fieldAttr['help'] = 'Enable if Dolibarr ECM directory is mounted as Nextcloud external storage';

// ECM Auto-scan
$item = $formSetup->newItem('SEUP_ECM_AUTO_SCAN');
$item->setAsYesNo();
$item->fieldAttr['help'] = 'Automatically scan ECM folders for new files when accessing predmet pages';

// Test connection button (will be handled by JavaScript)
$item = $formSetup->newItem('NEXTCLOUD_TEST');
$item->fieldOverride = '<button type="button" id="testNextcloudBtn" class="button">Test Connection</button><div id="testResult" style="margin-top: 10px;"></div>';

// ECM Scan button
$item = $formSetup->newItem('ECM_SCAN_ALL');
$item->fieldOverride = '<button type="button" id="scanAllEcmBtn" class="button">Scan All ECM Folders</button><div id="scanResult" style="margin-top: 10px;"></div>';

// End of definition of parameters


$setupnotempty += count($formSetup->items);


$dirmodels = array_merge(array('/'), (array) $conf->modules_parts['models']);

$moduledir = 'seup';
$myTmpObjects = array();
// TODO Scan list of objects to fill this array
$myTmpObjects['myobject'] = array('label' => 'MyObject', 'includerefgeneration' => 0, 'includedocgeneration' => 0, 'class' => 'MyObject');

$tmpobjectkey = GETPOST('object', 'aZ09');
if ($tmpobjectkey && !array_key_exists($tmpobjectkey, $myTmpObjects)) {
	accessforbidden('Bad value for object. Hack attempt ?');
}


/*
 * Actions
 */

// For retrocompatibility Dolibarr < 15.0
if (versioncompare(explode('.', DOL_VERSION), array(15)) < 0 && $action == 'update' && !empty($user->admin)) {
	$formSetup->saveConfFromPost();
}

include DOL_DOCUMENT_ROOT.'/core/actions_setmoduleoptions.inc.php';

// Handle Nextcloud test connection
if ($action == 'test_nextcloud') {
    header('Content-Type: application/json');
    ob_end_clean();
    
    $test_url = GETPOST('url', 'alpha');
    $test_username = GETPOST('username', 'alpha');
    $test_password = GETPOST('password', 'alpha');
    
    if (empty($test_url) || empty($test_username) || empty($test_password)) {
        echo json_encode(['success' => false, 'error' => 'Missing configuration parameters']);
        exit;
    }
    
    // Test connection
    $url = $test_url . '/remote.php/dav/files/' . $test_username . '/';
    
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CUSTOMREQUEST => 'PROPFIND',
        CURLOPT_USERPWD => $test_username . ':' . $test_password,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_HTTPHEADER => ['Depth: 1']
    ]);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode === 207) {
        echo json_encode(['success' => true, 'message' => 'Nextcloud connection successful!']);
    } else {
        echo json_encode(['success' => false, 'error' => 'Connection failed (HTTP ' . $httpCode . ')']);
    }
    exit;
}

// Handle ECM scan all request
if ($action == 'scan_all_ecm') {
    header('Content-Type: application/json');
    ob_end_clean();
    
    require_once __DIR__ . '/../class/ecm_scanner.class.php';
    $result = ECM_Scanner::scanAllSeupFolders($db, $conf, $user, 100);
    
    echo json_encode($result);
    exit;
}

if ($action == 'updateMask') {
	$maskconst = GETPOST('maskconst', 'aZ09');
	$maskvalue = GETPOST('maskvalue', 'alpha');

	if ($maskconst && preg_match('/_MASK$/', $maskconst)) {
		$res = dolibarr_set_const($db, $maskconst, $maskvalue, 'chaine', 0, '', $conf->entity);
		if (!($res > 0)) {
			$error++;
		}
	}

	if (!$error) {
		setEventMessages($langs->trans("SetupSaved"), null, 'mesgs');
	} else {
		setEventMessages($langs->trans("Error"), null, 'errors');
	}
} elseif ($action == 'specimen' && $tmpobjectkey) {
	$modele = GETPOST('module', 'alpha');

	$className = $myTmpObjects[$tmpobjectkey]['class'];
	$tmpobject = new $className($db);
	'@phan-var-force MyObject $tmpobject';
	$tmpobject->initAsSpecimen();

	// Search template files
	$file = '';
	$className = '';
	$dirmodels = array_merge(array('/'), (array) $conf->modules_parts['models']);
	foreach ($dirmodels as $reldir) {
		$file = dol_buildpath($reldir."core/modules/seup/doc/pdf_".$modele."_".strtolower($tmpobjectkey).".modules.php", 0);
		if (file_exists($file)) {
			$className = "pdf_".$modele."_".strtolower($tmpobjectkey);
			break;
		}
	}

	if ($className !== '') {
		require_once $file;

		$module = new $className($db);
		'@phan-var-force ModelePDFMyObject $module';

		'@phan-var-force ModelePDFMyObject $module';

		if ($module->write_file($tmpobject, $langs) > 0) {
			header("Location: ".DOL_URL_ROOT."/document.php?modulepart=seup-".strtolower($tmpobjectkey)."&file=SPECIMEN.pdf");
			return;
		} else {
			setEventMessages($module->error, null, 'errors');
			dol_syslog($module->error, LOG_ERR);
		}
	} else {
		setEventMessages($langs->trans("ErrorModuleNotFound"), null, 'errors');
		dol_syslog($langs->trans("ErrorModuleNotFound"), LOG_ERR);
	}
} elseif ($action == 'setmod') {
	// TODO Check if numbering module chosen can be activated by calling method canBeActivated
	if (!empty($tmpobjectkey)) {
		$constforval = 'SEUP_'.strtoupper($tmpobjectkey)."_ADDON";
		dolibarr_set_const($db, $constforval, $value, 'chaine', 0, '', $conf->entity);
	}
} elseif ($action == 'set') {
	// Activate a model
	$ret = addDocumentModel($value, $type, $label, $scandir);
} elseif ($action == 'del') {
	$ret = delDocumentModel($value, $type);
	if ($ret > 0) {
		if (!empty($tmpobjectkey)) {
			$constforval = 'SEUP_'.strtoupper($tmpobjectkey).'_ADDON_PDF';
			if (getDolGlobalString($constforval) == "$value") {
				dolibarr_del_const($db, $constforval, $conf->entity);
			}
		}
	}
} elseif ($action == 'setdoc') {
	// Set or unset default model
	if (!empty($tmpobjectkey)) {
		$constforval = 'SEUP_'.strtoupper($tmpobjectkey).'_ADDON_PDF';
		if (dolibarr_set_const($db, $constforval, $value, 'chaine', 0, '', $conf->entity)) {
			// The constant that was read before the new set
			// We therefore requires a variable to have a coherent view
			$conf->global->{$constforval} = $value;
		}

		// We disable/enable the document template (into llx_document_model table)
		$ret = delDocumentModel($value, $type);
		if ($ret > 0) {
			$ret = addDocumentModel($value, $type, $label, $scandir);
		}
	}
} elseif ($action == 'unsetdoc') {
	if (!empty($tmpobjectkey)) {
		$constforval = 'SEUP_'.strtoupper($tmpobjectkey).'_ADDON_PDF';
		dolibarr_del_const($db, $constforval, $conf->entity);
	}
}

$action = 'edit';


/*
 * View
 */

$form = new Form($db);

$help_url = '';
$title = "SEUPSetup";

llxHeader('', $langs->trans($title), $help_url, '', 0, 0, '', '', '', 'mod-seup page-admin');

// Modern design assets
print '<meta name="viewport" content="width=device-width, initial-scale=1">';
print '<link rel="preconnect" href="https://fonts.googleapis.com">';
print '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>';
print '<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">';
print '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">';
print '<link href="/custom/seup/css/seup-modern.css" rel="stylesheet">';

// Subheader
$linkback = '<a href="'.($backtopage ? $backtopage : DOL_URL_ROOT.'/admin/modules.php?restore_lastsearch_values=1').'">'.$langs->trans("BackToModuleList").'</a>';

// Custom header with modern design
print '<div class="seup-admin-header">';
print '<div class="seup-admin-header-content">';
print '<div class="seup-admin-icon"><i class="fas fa-cogs"></i></div>';
print '<div class="seup-admin-title-section">';
print '<h1 class="seup-admin-title">' . $langs->trans($title) . '</h1>';
print '<p class="seup-admin-subtitle">Konfigurirajte SEUP modul i Nextcloud integraciju</p>';
print '</div>';
print '</div>';
print '<div class="seup-admin-actions">';
print $linkback;
print '</div>';
print '</div>';

// Configuration header
$head = seupAdminPrepareHead();
print '<div class="seup-admin-tabs">';
print dol_get_fiche_head($head, 'settings', '', 0, 'seup@seup');
print '</div>';

// Setup page goes here
print '<div class="seup-admin-container">';

// Welcome section
print '<div class="seup-admin-welcome">';
print '<div class="seup-welcome-icon"><i class="fas fa-rocket"></i></div>';
print '<div class="seup-welcome-content">';
print '<h3>Dobrodošli u SEUP konfiguraciju</h3>';
print '<p>Konfigurirajte osnovne parametre modula i Nextcloud integraciju za optimalno iskustvo rada.</p>';
print '</div>';
print '</div>';

// Configuration sections

/*if ($action == 'edit') {
 print $formSetup->generateOutput(true);
 print '<br>';
 } elseif (!empty($formSetup->items)) {
 print $formSetup->generateOutput();
 print '<div class="tabsAction">';
 print '<a class="butAction" href="'.$_SERVER["PHP_SELF"].'?action=edit&token='.newToken().'">'.$langs->trans("Modify").'</a>';
 print '</div>';
 }
 */

// Basic Configuration Section
print '<div class="seup-config-section">';
print '<div class="seup-section-header">';
print '<div class="seup-section-icon"><i class="fas fa-sliders-h"></i></div>';
print '<h3 class="seup-section-title">Osnovne Postavke</h3>';
print '<p class="seup-section-description">Konfigurirajte osnovne parametre SEUP modula</p>';
print '</div>';
print '<div class="seup-section-content">';
if (!empty($formSetup->items)) {
	print $formSetup->generateOutput(true);
}
print '</div>';
print '</div>';

// Nextcloud Integration Section
print '<div class="seup-config-section seup-nextcloud-section">';
print '<div class="seup-section-header">';
print '<div class="seup-section-icon"><i class="fab fa-cloud"></i></div>';
print '<h3 class="seup-section-title">Nextcloud Integracija</h3>';
print '<p class="seup-section-description">Konfigurirajte sinkronizaciju dokumenata s Nextcloud serverom</p>';
print '</div>';
print '<div class="seup-section-content">';

// Nextcloud status indicator
$nextcloud_url = getDolGlobalString('NEXTCLOUD_URL', '');
$nextcloud_username = getDolGlobalString('NEXTCLOUD_USERNAME', '');
$nextcloud_password = getDolGlobalString('NEXTCLOUD_PASSWORD', '');
$nextcloud_enabled = getDolGlobalString('NEXTCLOUD_ENABLED', '0');

$status_class = 'warning';
$status_text = 'Nije konfigurirano';
$status_icon = 'fa-exclamation-triangle';

if (!empty($nextcloud_url) && !empty($nextcloud_username) && !empty($nextcloud_password)) {
    if ($nextcloud_enabled) {
        $status_class = 'success';
        $status_text = 'Aktivno i konfigurirano';
        $status_icon = 'fa-check-circle';
    } else {
        $status_class = 'info';
        $status_text = 'Konfigurirano ali neaktivno';
        $status_icon = 'fa-pause-circle';
    }
} elseif (!empty($nextcloud_url) || !empty($nextcloud_username)) {
    $status_class = 'warning';
    $status_text = 'Djelomično konfigurirano';
    $status_icon = 'fa-exclamation-triangle';
}

print '<div class="seup-status-card seup-status-' . $status_class . '">';
print '<div class="seup-status-icon"><i class="fas ' . $status_icon . '"></i></div>';
print '<div class="seup-status-content">';
print '<h4>Status Nextcloud Integracije</h4>';
print '<p>' . $status_text . '</p>';
print '</div>';
print '</div>';

print '</div>';
print '</div>';

print '</div>'; // seup-admin-container

// Add JavaScript for test connection
print '<script>
document.addEventListener("DOMContentLoaded", function() {
    const testBtn = document.getElementById("testNextcloudBtn");
    const testResult = document.getElementById("testResult");
    const scanAllBtn = document.getElementById("scanAllEcmBtn");
    const scanResult = document.getElementById("scanResult");
    
    if (testBtn) {
        testBtn.addEventListener("click", function() {
            this.disabled = true;
            this.innerHTML = "<i class=\'fas fa-spinner fa-spin\'></i> Testiram...";
            testResult.innerHTML = "";
            
            const formData = new FormData();
            formData.append("action", "test_nextcloud");
            formData.append("token", "'.newToken().'");
            formData.append("url", document.querySelector("input[name=\'NEXTCLOUD_URL\']").value);
            formData.append("username", document.querySelector("input[name=\'NEXTCLOUD_USERNAME\']").value);
            formData.append("password", document.querySelector("input[name=\'NEXTCLOUD_PASSWORD\']").value);
            
            fetch("", {
                method: "POST",
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    testResult.innerHTML = "<div class=\'seup-test-success\'><i class=\'fas fa-check-circle\'></i> " + data.message + "</div>";
                } else {
                    testResult.innerHTML = "<div class=\'seup-test-error\'><i class=\'fas fa-times-circle\'></i> " + data.error + "</div>";
                }
            })
            .catch(error => {
                testResult.innerHTML = "<div class=\'seup-test-error\'><i class=\'fas fa-times-circle\'></i> Veza neuspješna</div>";
            })
            .finally(() => {
                this.disabled = false;
                this.innerHTML = "<i class=\'fas fa-plug\'></i> Test Connection";
            });
        });
    }
    
    if (scanAllBtn) {
        scanAllBtn.addEventListener("click", function() {
            this.disabled = true;
            this.innerHTML = "<i class=\'fas fa-spinner fa-spin\'></i> Skeniram...";
            scanResult.innerHTML = "";
            
            const formData = new FormData();
            formData.append("action", "scan_all_ecm");
            formData.append("token", "'.newToken().'");
            
            fetch("", {
                method: "POST",
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    scanResult.innerHTML = "<div class=\'seup-test-success\'><i class=\'fas fa-check-circle\'></i> " + data.message + "</div>";
                } else {
                    scanResult.innerHTML = "<div class=\'seup-test-error\'><i class=\'fas fa-times-circle\'></i> " + data.error + "</div>";
                }
            })
            .catch(error => {
                scanResult.innerHTML = "<div class=\'seup-test-error\'><i class=\'fas fa-times-circle\'></i> Skeniranje neuspješno</div>";
            })
            .finally(() => {
                this.disabled = false;
                this.innerHTML = "<i class=\'fas fa-search\'></i> Scan All ECM Folders";
            });
        });
    }
});
</script>';

// Add custom CSS for admin page
print '<style>
/* SEUP Admin Page Styles */
.seup-admin-header {
    background: linear-gradient(135deg, var(--primary-500), var(--primary-600));
    color: white;
    padding: var(--space-8) var(--space-6);
    margin: -20px -20px var(--space-6) -20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-radius: 0 0 var(--radius-2xl) var(--radius-2xl);
    box-shadow: var(--shadow-lg);
}

.seup-admin-header-content {
    display: flex;
    align-items: center;
    gap: var(--space-4);
}

.seup-admin-icon {
    width: 64px;
    height: 64px;
    background: rgba(255, 255, 255, 0.2);
    border-radius: var(--radius-xl);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 24px;
}

.seup-admin-title {
    font-size: var(--text-3xl);
    font-weight: var(--font-bold);
    margin: 0;
    text-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
}

.seup-admin-subtitle {
    font-size: var(--text-lg);
    margin: var(--space-2) 0 0 0;
    opacity: 0.9;
    font-weight: var(--font-medium);
}

.seup-admin-actions a {
    background: rgba(255, 255, 255, 0.2);
    color: white;
    padding: var(--space-3) var(--space-6);
    border-radius: var(--radius-lg);
    text-decoration: none;
    font-weight: var(--font-medium);
    transition: all var(--transition-fast);
    backdrop-filter: blur(10px);
}

.seup-admin-actions a:hover {
    background: rgba(255, 255, 255, 0.3);
    color: white;
    text-decoration: none;
    transform: translateY(-2px);
}

.seup-admin-tabs {
    margin: var(--space-6) 0;
}

.seup-admin-container {
    max-width: 1200px;
    margin: 0 auto;
}

.seup-admin-welcome {
    background: linear-gradient(135deg, var(--accent-50), var(--accent-100));
    border: 1px solid var(--accent-200);
    border-radius: var(--radius-2xl);
    padding: var(--space-6);
    margin-bottom: var(--space-8);
    display: flex;
    align-items: center;
    gap: var(--space-4);
}

.seup-welcome-icon {
    width: 48px;
    height: 48px;
    background: linear-gradient(135deg, var(--accent-500), var(--accent-600));
    border-radius: var(--radius-xl);
    display: flex;
    align-items: center;
    justify-content: center;
    color: white;
    font-size: 20px;
}

.seup-welcome-content h3 {
    font-size: var(--text-xl);
    font-weight: var(--font-semibold);
    color: var(--accent-800);
    margin: 0 0 var(--space-2) 0;
}

.seup-welcome-content p {
    color: var(--accent-700);
    margin: 0;
    line-height: var(--leading-relaxed);
}

.seup-config-section {
    background: white;
    border-radius: var(--radius-2xl);
    box-shadow: var(--shadow-lg);
    margin-bottom: var(--space-6);
    overflow: hidden;
    border: 1px solid var(--neutral-200);
}

.seup-section-header {
    background: linear-gradient(135deg, var(--secondary-50), var(--secondary-100));
    padding: var(--space-6);
    border-bottom: 1px solid var(--secondary-200);
    display: flex;
    align-items: center;
    gap: var(--space-4);
}

.seup-section-icon {
    width: 48px;
    height: 48px;
    background: linear-gradient(135deg, var(--secondary-500), var(--secondary-600));
    border-radius: var(--radius-xl);
    display: flex;
    align-items: center;
    justify-content: center;
    color: white;
    font-size: 18px;
}

.seup-section-title {
    font-size: var(--text-xl);
    font-weight: var(--font-semibold);
    color: var(--secondary-900);
    margin: 0;
}

.seup-section-description {
    color: var(--secondary-600);
    margin: var(--space-1) 0 0 0;
    font-size: var(--text-sm);
}

.seup-section-content {
    padding: var(--space-6);
}

.seup-nextcloud-section .seup-section-icon {
    background: linear-gradient(135deg, #0082c9, #0066a1);
}

.seup-status-card {
    padding: var(--space-4);
    border-radius: var(--radius-lg);
    margin-bottom: var(--space-4);
    display: flex;
    align-items: center;
    gap: var(--space-3);
    border: 1px solid;
}

.seup-status-success {
    background: var(--success-50);
    border-color: var(--success-200);
    color: var(--success-800);
}

.seup-status-warning {
    background: var(--warning-50);
    border-color: var(--warning-200);
    color: var(--warning-800);
}

.seup-status-info {
    background: var(--primary-50);
    border-color: var(--primary-200);
    color: var(--primary-800);
}

.seup-status-icon {
    width: 40px;
    height: 40px;
    border-radius: var(--radius-lg);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 18px;
}

.seup-status-success .seup-status-icon {
    background: var(--success-100);
    color: var(--success-600);
}

.seup-status-warning .seup-status-icon {
    background: var(--warning-100);
    color: var(--warning-600);
}

.seup-status-info .seup-status-icon {
    background: var(--primary-100);
    color: var(--primary-600);
}

.seup-status-content h4 {
    margin: 0 0 var(--space-1) 0;
    font-size: var(--text-base);
    font-weight: var(--font-semibold);
}

.seup-status-content p {
    margin: 0;
    font-size: var(--text-sm);
    opacity: 0.8;
}

/* Enhanced form styling */
.form-setup table {
    background: white;
    border-radius: var(--radius-lg);
    overflow: hidden;
    box-shadow: var(--shadow-sm);
    border: 1px solid var(--neutral-200);
}

.form-setup table tr:nth-child(even) {
    background: var(--neutral-25);
}

.form-setup table td {
    padding: var(--space-4);
    border-bottom: 1px solid var(--neutral-100);
}

.form-setup table td:first-child {
    font-weight: var(--font-medium);
    color: var(--secondary-700);
    width: 30%;
}

.form-setup input[type="text"],
.form-setup input[type="password"],
.form-setup select,
.form-setup textarea {
    border: 1px solid var(--neutral-300);
    border-radius: var(--radius-lg);
    padding: var(--space-3);
    font-size: var(--text-base);
    transition: all var(--transition-fast);
    background: white;
}

.form-setup input:focus,
.form-setup select:focus,
.form-setup textarea:focus {
    outline: none;
    border-color: var(--primary-500);
    box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
}

/* Test connection button styling */
#testNextcloudBtn {
    background: linear-gradient(135deg, var(--primary-500), var(--primary-600));
    color: white;
    border: none;
    padding: var(--space-3) var(--space-6);
    border-radius: var(--radius-lg);
    font-weight: var(--font-medium);
    cursor: pointer;
    transition: all var(--transition-normal);
    display: flex;
    align-items: center;
    gap: var(--space-2);
    font-size: var(--text-sm);
}

#testNextcloudBtn:hover {
    background: linear-gradient(135deg, var(--primary-600), var(--primary-700));
    transform: translateY(-2px);
    box-shadow: var(--shadow-lg);
}

#testNextcloudBtn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
    transform: none;
}

/* Test result styling */
.seup-test-success {
    background: var(--success-50);
    color: var(--success-800);
    padding: var(--space-3) var(--space-4);
    border-radius: var(--radius-lg);
    border: 1px solid var(--success-200);
    display: flex;
    align-items: center;
    gap: var(--space-2);
    margin-top: var(--space-3);
    animation: slideInUp 0.3s ease-out;
}

.seup-test-error {
    background: var(--error-50);
    color: var(--error-800);
    padding: var(--space-3) var(--space-4);
    border-radius: var(--radius-lg);
    border: 1px solid var(--error-200);
    display: flex;
    align-items: center;
    gap: var(--space-2);
    margin-top: var(--space-3);
    animation: slideInUp 0.3s ease-out;
}

/* Enhanced tab styling */
.seup-admin-tabs .fiche_titre {
    background: white;
    border-radius: var(--radius-2xl);
    box-shadow: var(--shadow-lg);
    padding: 0;
    overflow: hidden;
    border: 1px solid var(--neutral-200);
}

.seup-admin-tabs .tabBar {
    background: linear-gradient(135deg, var(--neutral-50), var(--neutral-100));
    border-bottom: 1px solid var(--neutral-200);
}

.seup-admin-tabs .tabBar a {
    padding: var(--space-4) var(--space-6);
    color: var(--secondary-600);
    font-weight: var(--font-medium);
    border-radius: var(--radius-lg) var(--radius-lg) 0 0;
    transition: all var(--transition-fast);
}

.seup-admin-tabs .tabBar a.tabactive {
    background: white;
    color: var(--primary-600);
    border-bottom: 3px solid var(--primary-500);
}

.seup-admin-tabs .tabBar a:hover {
    background: var(--primary-50);
    color: var(--primary-700);
}

/* Animation */
@keyframes slideInUp {
    from {
        opacity: 0;
        transform: translateY(20px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

/* Responsive design */
@media (max-width: 768px) {
    .seup-admin-header {
        flex-direction: column;
        text-align: center;
        gap: var(--space-4);
    }
    
    .seup-admin-header-content {
        flex-direction: column;
        text-align: center;
    }
    
    .seup-config-section {
        margin: 0 -10px var(--space-6) -10px;
        border-radius: var(--radius-xl);
    }
}
</style>';

foreach ($myTmpObjects as $myTmpObjectKey => $myTmpObjectArray) {
	if (!empty($myTmpObjectArray['includerefgeneration'])) {
		/*
		 * Orders Numbering model
		 */
		$setupnotempty++;

		print load_fiche_titre($langs->trans("NumberingModules", $myTmpObjectArray['label']), '', '');

		print '<table class="noborder centpercent">';
		print '<tr class="liste_titre">';
		print '<td>'.$langs->trans("Name").'</td>';
		print '<td>'.$langs->trans("Description").'</td>';
		print '<td class="nowrap">'.$langs->trans("Example").'</td>';
		print '<td class="center" width="60">'.$langs->trans("Status").'</td>';
		print '<td class="center" width="16">'.$langs->trans("ShortInfo").'</td>';
		print '</tr>'."\n";

		clearstatcache();

		foreach ($dirmodels as $reldir) {
			$dir = dol_buildpath($reldir."core/modules/".$moduledir);

			if (is_dir($dir)) {
				$handle = opendir($dir);
				if (is_resource($handle)) {
					while (($file = readdir($handle)) !== false) {
						if (strpos($file, 'mod_'.strtolower($myTmpObjectKey).'_') === 0 && substr($file, dol_strlen($file) - 3, 3) == 'php') {
							$file = substr($file, 0, dol_strlen($file) - 4);

							require_once $dir.'/'.$file.'.php';

							$module = new $file($db);
							'@phan-var-force ModeleNumRefMyObject $module';

							// Show modules according to features level
							if ($module->version == 'development' && getDolGlobalInt('MAIN_FEATURES_LEVEL') < 2) {
								continue;
							}
							if ($module->version == 'experimental' && getDolGlobalInt('MAIN_FEATURES_LEVEL') < 1) {
								continue;
							}

							if ($module->isEnabled()) {
								dol_include_once('/'.$moduledir.'/class/'.strtolower($myTmpObjectKey).'.class.php');

								print '<tr class="oddeven"><td>'.$module->getName($langs)."</td><td>\n";
								print $module->info($langs);
								print '</td>';

								// Show example of numbering model
								print '<td class="nowrap">';
								$tmp = $module->getExample();
								if (preg_match('/^Error/', $tmp)) {
									$langs->load("errors");
									print '<div class="error">'.$langs->trans($tmp).'</div>';
								} elseif ($tmp == 'NotConfigured') {
									print $langs->trans($tmp);
								} else {
									print $tmp;
								}
								print '</td>'."\n";

								print '<td class="center">';
								$constforvar = 'SEUP_'.strtoupper($myTmpObjectKey).'_ADDON';
								if (getDolGlobalString($constforvar) == $file) {
									print img_picto($langs->trans("Activated"), 'switch_on');
								} else {
									print '<a href="'.$_SERVER["PHP_SELF"].'?action=setmod&token='.newToken().'&object='.strtolower($myTmpObjectKey).'&value='.urlencode($file).'">';
									print img_picto($langs->trans("Disabled"), 'switch_off');
									print '</a>';
								}
								print '</td>';

								$className = $myTmpObjectArray['class'];
								$mytmpinstance = new $className($db);
								'@phan-var-force MyObject $mytmpinstance';
								$mytmpinstance->initAsSpecimen();

								// Info
								$htmltooltip = '';
								$htmltooltip .= ''.$langs->trans("Version").': <b>'.$module->getVersion().'</b><br>';

								$nextval = $module->getNextValue($mytmpinstance);
								if ("$nextval" != $langs->trans("NotAvailable")) {  // Keep " on nextval
									$htmltooltip .= ''.$langs->trans("NextValue").': ';
									if ($nextval) {
										if (preg_match('/^Error/', $nextval) || $nextval == 'NotConfigured') {
											$nextval = $langs->trans($nextval);
										}
										$htmltooltip .= $nextval.'<br>';
									} else {
										$htmltooltip .= $langs->trans($module->error).'<br>';
									}
								}

								print '<td class="center">';
								print $form->textwithpicto('', $htmltooltip, 1, 0);
								print '</td>';

								print "</tr>\n";
							}
						}
					}
					closedir($handle);
				}
			}
		}
		print "</table><br>\n";
	}

	if (!empty($myTmpObjectArray['includedocgeneration'])) {
		/*
		 * Document templates generators
		 */
		$setupnotempty++;
		$type = strtolower($myTmpObjectKey);

		print load_fiche_titre($langs->trans("DocumentModules", $myTmpObjectKey), '', '');

		// Load array def with activated templates
		$def = array();
		$sql = "SELECT nom";
		$sql .= " FROM ".MAIN_DB_PREFIX."document_model";
		$sql .= " WHERE type = '".$db->escape($type)."'";
		$sql .= " AND entity = ".$conf->entity;
		$resql = $db->query($sql);
		if ($resql) {
			$i = 0;
			$num_rows = $db->num_rows($resql);
			while ($i < $num_rows) {
				$array = $db->fetch_array($resql);
				array_push($def, $array[0]);
				$i++;
			}
		} else {
			dol_print_error($db);
		}

		print '<table class="noborder centpercent">'."\n";
		print '<tr class="liste_titre">'."\n";
		print '<td>'.$langs->trans("Name").'</td>';
		print '<td>'.$langs->trans("Description").'</td>';
		print '<td class="center" width="60">'.$langs->trans("Status")."</td>\n";
		print '<td class="center" width="60">'.$langs->trans("Default")."</td>\n";
		print '<td class="center" width="38">'.$langs->trans("ShortInfo").'</td>';
		print '<td class="center" width="38">'.$langs->trans("Preview").'</td>';
		print "</tr>\n";

		clearstatcache();

		foreach ($dirmodels as $reldir) {
			foreach (array('', '/doc') as $valdir) {
				$realpath = $reldir."core/modules/".$moduledir.$valdir;
				$dir = dol_buildpath($realpath);

				if (is_dir($dir)) {
					$handle = opendir($dir);
					if (is_resource($handle)) {
						$filelist = array();
						while (($file = readdir($handle)) !== false) {
							$filelist[] = $file;
						}
						closedir($handle);
						arsort($filelist);

						foreach ($filelist as $file) {
							if (preg_match('/\.modules\.php$/i', $file) && preg_match('/^(pdf_|doc_)/', $file)) {
								if (file_exists($dir.'/'.$file)) {
									$name = substr($file, 4, dol_strlen($file) - 16);
									$className = substr($file, 0, dol_strlen($file) - 12);

									require_once $dir.'/'.$file;
									$module = new $className($db);
									'@phan-var-force ModelePDFMyObject $module';

									$modulequalified = 1;
									if ($module->version == 'development' && getDolGlobalInt('MAIN_FEATURES_LEVEL') < 2) {
										$modulequalified = 0;
									}
									if ($module->version == 'experimental' && getDolGlobalInt('MAIN_FEATURES_LEVEL') < 1) {
										$modulequalified = 0;
									}

									if ($modulequalified) {
										print '<tr class="oddeven"><td width="100">';
										print(empty($module->name) ? $name : $module->name);
										print "</td><td>\n";
										if (method_exists($module, 'info')) {
											print $module->info($langs);  // @phan-suppress-current-line PhanUndeclaredMethod
										} else {
											print $module->description;
										}
										print '</td>';

										// Active
										if (in_array($name, $def)) {
											print '<td class="center">'."\n";
											print '<a href="'.$_SERVER["PHP_SELF"].'?action=del&token='.newToken().'&value='.urlencode($name).'">';
											print img_picto($langs->trans("Enabled"), 'switch_on');
											print '</a>';
											print '</td>';
										} else {
											print '<td class="center">'."\n";
											print '<a href="'.$_SERVER["PHP_SELF"].'?action=set&token='.newToken().'&value='.urlencode($name).'&scan_dir='.urlencode($module->scandir).'&label='.urlencode($module->name).'">'.img_picto($langs->trans("Disabled"), 'switch_off').'</a>';
											print "</td>";
										}

										// Default
										print '<td class="center">';
										$constforvar = 'SEUP_'.strtoupper($myTmpObjectKey).'_ADDON_PDF';
										if (getDolGlobalString($constforvar) == $name) {
											//print img_picto($langs->trans("Default"), 'on');
											// Even if choice is the default value, we allow to disable it. Replace this with previous line if you need to disable unset
											print '<a href="'.$_SERVER["PHP_SELF"].'?action=unsetdoc&token='.newToken().'&object='.urlencode(strtolower($myTmpObjectKey)).'&value='.urlencode($name).'&scan_dir='.urlencode($module->scandir).'&label='.urlencode($module->name).'&amp;type='.urlencode($type).'" alt="'.$langs->trans("Disable").'">'.img_picto($langs->trans("Enabled"), 'on').'</a>';
										} else {
											print '<a href="'.$_SERVER["PHP_SELF"].'?action=setdoc&token='.newToken().'&object='.urlencode(strtolower($myTmpObjectKey)).'&value='.urlencode($name).'&scan_dir='.urlencode($module->scandir).'&label='.urlencode($module->name).'" alt="'.$langs->trans("Default").'">'.img_picto($langs->trans("Disabled"), 'off').'</a>';
										}
										print '</td>';

										// Info
										$htmltooltip = ''.$langs->trans("Name").': '.$module->name;
										$htmltooltip .= '<br>'.$langs->trans("Type").': '.($module->type ? $module->type : $langs->trans("Unknown"));
										if ($module->type == 'pdf') {
											$htmltooltip .= '<br>'.$langs->trans("Width").'/'.$langs->trans("Height").': '.$module->page_largeur.'/'.$module->page_hauteur;
										}
										$htmltooltip .= '<br>'.$langs->trans("Path").': '.preg_replace('/^\//', '', $realpath).'/'.$file;

										$htmltooltip .= '<br><br><u>'.$langs->trans("FeaturesSupported").':</u>';
										$htmltooltip .= '<br>'.$langs->trans("Logo").': '.yn($module->option_logo, 1, 1);
										$htmltooltip .= '<br>'.$langs->trans("MultiLanguage").': '.yn($module->option_multilang, 1, 1);

										print '<td class="center">';
										print $form->textwithpicto('', $htmltooltip, 1, 0);
										print '</td>';

										// Preview
										print '<td class="center">';
										if ($module->type == 'pdf') {
											$newname = preg_replace('/_'.preg_quote(strtolower($myTmpObjectKey), '/').'/', '', $name);
											print '<a href="'.$_SERVER["PHP_SELF"].'?action=specimen&module='.urlencode($newname).'&object='.urlencode($myTmpObjectKey).'">'.img_object($langs->trans("Preview"), 'pdf').'</a>';
										} else {
											print img_object($langs->transnoentitiesnoconv("PreviewNotAvailable"), 'generic');
										}
										print '</td>';

										print "</tr>\n";
									}
								}
							}
						}
					}
				}
			}
		}

		print '</table>';
	}
}

if (empty($setupnotempty)) {
	print '<br>'.$langs->trans("NothingToSetup");
}

// Page end
print dol_get_fiche_end();

llxFooter();
$db->close();
