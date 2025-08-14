<?php
/* Copyright (C) 2004-2017 Laurent Destailleur  <eldy@users.sourceforge.net>
 * Copyright (C) 2025		SuperAdmin
 * Copyright (C) 2024       Frédéric France         <frederic.france@free.fr>
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
 * \file    seup/admin/about.php
 * \ingroup seup
 * \brief   About page of module SEUP.
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
require_once DOL_DOCUMENT_ROOT.'/core/lib/admin.lib.php';
require_once DOL_DOCUMENT_ROOT.'/core/lib/functions2.lib.php';
require_once '../lib/seup.lib.php';

/**
 * @var Conf $conf
 * @var DoliDB $db
 * @var HookManager $hookmanager
 * @var Translate $langs
 * @var User $user
 */

// Translations
$langs->loadLangs(array("errors", "admin", "seup@seup"));

// Access control
if (!$user->admin) {
	accessforbidden();
}

// Parameters
$action = GETPOST('action', 'aZ09');
$backtopage = GETPOST('backtopage', 'alpha');


/*
 * Actions
 */

// None


/*
 * View
 */

$form = new Form($db);

$help_url = '';
$title = "SEUPSetup";

llxHeader('', $langs->trans($title), $help_url, '', 0, 0, '', '', '', 'mod-seup page-admin_about');

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
print '<div class="seup-admin-icon"><i class="fas fa-info-circle"></i></div>';
print '<div class="seup-admin-title-section">';
print '<h1 class="seup-admin-title">O SEUP Modulu</h1>';
print '<p class="seup-admin-subtitle">Informacije o modulu, licenci i autorskim pravima</p>';
print '</div>';
print '</div>';
print '<div class="seup-admin-actions">';
print $linkback;
print '</div>';
print '</div>';

// Configuration header
$head = seupAdminPrepareHead();
print '<div class="seup-admin-tabs">';
print dol_get_fiche_head($head, 'about', '', 0, 'seup@seup');
print '</div>';

// About page content
print '<div class="seup-about-container">';

// Module Info Section
print '<div class="seup-about-section">';
print '<div class="seup-section-header">';
print '<div class="seup-section-icon"><i class="fas fa-cube"></i></div>';
print '<div>';
print '<h3 class="seup-section-title">SEUP - Sustav Elektronskog Uredskog Poslovanja</h3>';
print '<p class="seup-section-description">Moderni modul za upravljanje dokumentima i predmetima u javnoj upravi</p>';
print '</div>';
print '</div>';
print '<div class="seup-section-content">';
print '<div class="seup-info-grid">';

print '<div class="seup-info-card">';
print '<div class="seup-info-icon"><i class="fas fa-tag"></i></div>';
print '<div class="seup-info-content">';
print '<h4>Verzija</h4>';
print '<p>14.0.4</p>';
print '</div>';
print '</div>';

print '<div class="seup-info-card">';
print '<div class="seup-info-icon"><i class="fas fa-calendar"></i></div>';
print '<div class="seup-info-content">';
print '<h4>Datum izdanja</h4>';
print '<p>' . date('d.m.Y') . '</p>';
print '</div>';
print '</div>';

print '<div class="seup-info-card">';
print '<div class="seup-info-icon"><i class="fas fa-code"></i></div>';
print '<div class="seup-info-content">';
print '<h4>Kompatibilnost</h4>';
print '<p>Dolibarr 19.0+</p>';
print '</div>';
print '</div>';

print '<div class="seup-info-card">';
print '<div class="seup-info-icon"><i class="fas fa-shield-alt"></i></div>';
print '<div class="seup-info-content">';
print '<h4>Licenca</h4>';
print '<p>Vlasnička</p>';
print '</div>';
print '</div>';

print '</div>'; // seup-info-grid
print '</div>'; // seup-section-content
print '</div>'; // seup-about-section

// Features Section
print '<div class="seup-about-section">';
print '<div class="seup-section-header">';
print '<div class="seup-section-icon"><i class="fas fa-star"></i></div>';
print '<div>';
print '<h3 class="seup-section-title">Značajke Modula</h3>';
print '<p class="seup-section-description">Napredne funkcionalnosti za upravljanje uredskim poslovanjem</p>';
print '</div>';
print '</div>';
print '<div class="seup-section-content">';
print '<div class="seup-features-grid">';

$features = [
    ['icon' => 'fas fa-folder-plus', 'title' => 'Upravljanje predmetima', 'desc' => 'Kreiranje i praćenje predmeta s klasifikacijskim oznakama'],
    ['icon' => 'fas fa-file-upload', 'title' => 'Upravljanje dokumentima', 'desc' => 'Upload, pregled i organizacija dokumenata'],
    ['icon' => 'fas fa-building', 'title' => 'Oznake ustanova', 'desc' => 'Konfiguracija osnovnih podataka ustanove'],
    ['icon' => 'fas fa-users', 'title' => 'Interne oznake korisnika', 'desc' => 'Upravljanje korisničkim oznakama i radnim mjestima'],
    ['icon' => 'fas fa-sitemap', 'title' => 'Plan klasifikacijskih oznaka', 'desc' => 'Hijerarhijski sustav klasifikacije'],
    ['icon' => 'fas fa-tags', 'title' => 'Tagovi', 'desc' => 'Fleksibilno označavanje s color pickerom'],
    ['icon' => 'fas fa-chart-bar', 'title' => 'Statistike', 'desc' => 'Pregled aktivnosti i izvještaji'],
    ['icon' => 'fas fa-cloud', 'title' => 'Nextcloud integracija', 'desc' => 'Sinkronizacija dokumenata s vanjskim sustavima']
];

foreach ($features as $feature) {
    print '<div class="seup-feature-card">';
    print '<div class="seup-feature-icon"><i class="' . $feature['icon'] . '"></i></div>';
    print '<div class="seup-feature-content">';
    print '<h4>' . $feature['title'] . '</h4>';
    print '<p>' . $feature['desc'] . '</p>';
    print '</div>';
    print '</div>';
}

print '</div>'; // seup-features-grid
print '</div>'; // seup-section-content
print '</div>'; // seup-about-section

// License Section
print '<div class="seup-about-section seup-license-section">';
print '<div class="seup-section-header">';
print '<div class="seup-section-icon"><i class="fas fa-certificate"></i></div>';
print '<div>';
print '<h3 class="seup-section-title">Licenca i Autorska Prava</h3>';
print '<p class="seup-section-description">Informacije o vlasništvu i uvjetima korištenja</p>';
print '</div>';
print '</div>';
print '<div class="seup-section-content">';
print '<div class="seup-license-content">';

print '<div class="seup-license-warning">';
print '<div class="seup-warning-icon"><i class="fas fa-exclamation-triangle"></i></div>';
print '<div class="seup-warning-content">';
print '<h4>Plaćena Licenca - Sva Prava Pridržana</h4>';
print '<p>Ovaj softver je vlasnički i zaštićen je autorskim i srodnim pravima.</p>';
print '</div>';
print '</div>';

print '<div class="seup-copyright-info">';
print '<h4><i class="fas fa-copyright me-2"></i>Autorska Prava</h4>';
print '<div class="seup-authors">';
print '<div class="seup-author">';
print '<div class="seup-author-avatar"><i class="fas fa-user"></i></div>';
print '<div class="seup-author-info">';
print '<h5>Tomislav Galić</h5>';
print '<p>Glavni developer</p>';
print '<a href="mailto:tomislav@8core.hr"><i class="fas fa-envelope me-1"></i>tomislav@8core.hr</a>';
print '</div>';
print '</div>';
print '<div class="seup-author">';
print '<div class="seup-author-avatar"><i class="fas fa-user"></i></div>';
print '<div class="seup-author-info">';
print '<h5>Marko Šimunović</h5>';
print '<p>Suradnik</p>';
print '<a href="mailto:marko@8core.hr"><i class="fas fa-envelope me-1"></i>marko@8core.hr</a>';
print '</div>';
print '</div>';
print '</div>';
print '</div>';

print '<div class="seup-company-info">';
print '<h4><i class="fas fa-building me-2"></i>8Core Association</h4>';
print '<div class="seup-contact-grid">';
print '<div class="seup-contact-item">';
print '<i class="fas fa-globe"></i>';
print '<a href="https://8core.hr" target="_blank">https://8core.hr</a>';
print '</div>';
print '<div class="seup-contact-item">';
print '<i class="fas fa-envelope"></i>';
print '<a href="mailto:info@8core.hr">info@8core.hr</a>';
print '</div>';
print '<div class="seup-contact-item">';
print '<i class="fas fa-phone"></i>';
print '<a href="tel:+385099851071">+385 099 851 0717</a>';
print '</div>';
print '<div class="seup-contact-item">';
print '<i class="fas fa-calendar"></i>';
print '<span>2014 - ' . date('Y') . '</span>';
print '</div>';
print '</div>';
print '</div>';

print '<div class="seup-legal-notice">';
print '<h4><i class="fas fa-gavel me-2"></i>Pravne Napomene</h4>';
print '<div class="seup-legal-content">';
print '<p><strong>Zabranjeno je:</strong></p>';
print '<ul>';
print '<li>Umnožavanje bez pismenog odobrenja</li>';
print '<li>Distribucija ili dijeljenje koda</li>';
print '<li>Mijenjanje ili prerada softvera</li>';
print '<li>Objavljivanje ili komercijalna eksploatacija</li>';
print '</ul>';
print '<p class="seup-legal-reference">';
print '<strong>Pravni okvir:</strong> Zakon o autorskom pravu i srodnim pravima (NN 167/03, 79/07, 80/11, 125/17) ';
print 'i Kazneni zakon (NN 125/11, 144/12, 56/15), članak 228.';
print '</p>';
print '<p class="seup-legal-penalty">';
print '<strong>Kazne:</strong> Prekršitelji se mogu kazniti novčanom kaznom ili zatvorom do jedne godine, ';
print 'uz mogućnost oduzimanja protivpravne imovinske koristi.';
print '</p>';
print '</div>';
print '</div>';

print '</div>'; // seup-license-content
print '</div>'; // seup-section-content
print '</div>'; // seup-license-section

// Support Section
print '<div class="seup-about-section">';
print '<div class="seup-section-header">';
print '<div class="seup-section-icon"><i class="fas fa-life-ring"></i></div>';
print '<div>';
print '<h3 class="seup-section-title">Podrška i Kontakt</h3>';
print '<p class="seup-section-description">Za sva pitanja, zahtjeve za licenciranjem ili tehničku podršku</p>';
print '</div>';
print '</div>';
print '<div class="seup-section-content">';
print '<div class="seup-support-cards">';

print '<div class="seup-support-card">';
print '<div class="seup-support-icon"><i class="fas fa-question-circle"></i></div>';
print '<h4>Tehnička Podrška</h4>';
print '<p>Za tehnička pitanja i probleme s modulom</p>';
print '<a href="mailto:info@8core.hr?subject=SEUP%20Tehnička%20Podrška" class="seup-support-btn">';
print '<i class="fas fa-envelope me-2"></i>Kontaktiraj podršku';
print '</a>';
print '</div>';

print '<div class="seup-support-card">';
print '<div class="seup-support-icon"><i class="fas fa-key"></i></div>';
print '<h4>Licenciranje</h4>';
print '<p>Za zahtjeve za dodatnim licencama</p>';
print '<a href="mailto:info@8core.hr?subject=SEUP%20Licenciranje" class="seup-support-btn">';
print '<i class="fas fa-handshake me-2"></i>Zahtjev za licencu';
print '</a>';
print '</div>';

print '<div class="seup-support-card">';
print '<div class="seup-support-icon"><i class="fas fa-cogs"></i></div>';
print '<h4>Prilagodbe</h4>';
print '<p>Za custom razvoj i prilagodbe</p>';
print '<a href="mailto:info@8core.hr?subject=SEUP%20Custom%20Razvoj" class="seup-support-btn">';
print '<i class="fas fa-code me-2"></i>Zatraži ponudu';
print '</a>';
print '</div>';

print '</div>'; // seup-support-cards
print '</div>'; // seup-section-content
print '</div>'; // seup-about-section

print '</div>'; // seup-about-container

// Add custom CSS for about page
print '<style>
.seup-about-container {
    max-width: 1200px;
    margin: 0 auto;
    padding: var(--space-6) 0;
}

.seup-about-section {
    background: white;
    border-radius: var(--radius-2xl);
    box-shadow: var(--shadow-lg);
    margin-bottom: var(--space-6);
    overflow: hidden;
    border: 1px solid var(--neutral-200);
}

.seup-info-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: var(--space-4);
}

.seup-info-card {
    background: var(--neutral-50);
    border: 1px solid var(--neutral-200);
    border-radius: var(--radius-lg);
    padding: var(--space-4);
    display: flex;
    align-items: center;
    gap: var(--space-3);
    transition: all var(--transition-normal);
}

.seup-info-card:hover {
    transform: translateY(-2px);
    box-shadow: var(--shadow-md);
    border-color: var(--primary-200);
}

.seup-info-icon {
    width: 40px;
    height: 40px;
    background: linear-gradient(135deg, var(--primary-500), var(--primary-600));
    border-radius: var(--radius-lg);
    display: flex;
    align-items: center;
    justify-content: center;
    color: white;
    font-size: 16px;
}

.seup-info-content h4 {
    margin: 0 0 var(--space-1) 0;
    font-size: var(--text-sm);
    font-weight: var(--font-semibold);
    color: var(--secondary-600);
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.seup-info-content p {
    margin: 0;
    font-size: var(--text-lg);
    font-weight: var(--font-semibold);
    color: var(--secondary-900);
}

.seup-features-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: var(--space-4);
}

.seup-feature-card {
    background: var(--neutral-50);
    border: 1px solid var(--neutral-200);
    border-radius: var(--radius-lg);
    padding: var(--space-4);
    transition: all var(--transition-normal);
}

.seup-feature-card:hover {
    transform: translateY(-4px);
    box-shadow: var(--shadow-lg);
    border-color: var(--primary-200);
}

.seup-feature-icon {
    width: 48px;
    height: 48px;
    background: linear-gradient(135deg, var(--accent-500), var(--accent-600));
    border-radius: var(--radius-xl);
    display: flex;
    align-items: center;
    justify-content: center;
    color: white;
    font-size: 20px;
    margin-bottom: var(--space-3);
}

.seup-feature-content h4 {
    margin: 0 0 var(--space-2) 0;
    font-size: var(--text-lg);
    font-weight: var(--font-semibold);
    color: var(--secondary-900);
}

.seup-feature-content p {
    margin: 0;
    color: var(--secondary-600);
    line-height: var(--leading-relaxed);
}

.seup-license-section .seup-section-header {
    background: linear-gradient(135deg, var(--error-50), var(--error-100));
    border-bottom-color: var(--error-200);
}

.seup-license-section .seup-section-icon {
    background: linear-gradient(135deg, var(--error-500), var(--error-600));
}

.seup-license-warning {
    background: linear-gradient(135deg, var(--error-50), var(--error-100));
    border: 1px solid var(--error-200);
    border-radius: var(--radius-lg);
    padding: var(--space-4);
    margin-bottom: var(--space-6);
    display: flex;
    align-items: center;
    gap: var(--space-3);
}

.seup-warning-icon {
    width: 48px;
    height: 48px;
    background: var(--error-500);
    border-radius: var(--radius-lg);
    display: flex;
    align-items: center;
    justify-content: center;
    color: white;
    font-size: 20px;
    flex-shrink: 0;
}

.seup-warning-content h4 {
    margin: 0 0 var(--space-2) 0;
    color: var(--error-800);
    font-size: var(--text-lg);
    font-weight: var(--font-bold);
}

.seup-warning-content p {
    margin: 0;
    color: var(--error-700);
    font-weight: var(--font-medium);
}

.seup-copyright-info {
    background: var(--neutral-50);
    border: 1px solid var(--neutral-200);
    border-radius: var(--radius-lg);
    padding: var(--space-6);
    margin-bottom: var(--space-4);
}

.seup-copyright-info h4 {
    margin: 0 0 var(--space-4) 0;
    color: var(--secondary-900);
    font-size: var(--text-lg);
    font-weight: var(--font-semibold);
}

.seup-authors {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: var(--space-4);
}

.seup-author {
    background: white;
    border: 1px solid var(--neutral-200);
    border-radius: var(--radius-lg);
    padding: var(--space-4);
    display: flex;
    align-items: center;
    gap: var(--space-3);
}

.seup-author-avatar {
    width: 48px;
    height: 48px;
    background: linear-gradient(135deg, var(--primary-500), var(--primary-600));
    border-radius: var(--radius-xl);
    display: flex;
    align-items: center;
    justify-content: center;
    color: white;
    font-size: 18px;
}

.seup-author-info h5 {
    margin: 0 0 var(--space-1) 0;
    font-size: var(--text-base);
    font-weight: var(--font-semibold);
    color: var(--secondary-900);
}

.seup-author-info p {
    margin: 0 0 var(--space-2) 0;
    font-size: var(--text-sm);
    color: var(--secondary-600);
}

.seup-author-info a {
    color: var(--primary-600);
    text-decoration: none;
    font-size: var(--text-sm);
    font-weight: var(--font-medium);
}

.seup-author-info a:hover {
    color: var(--primary-700);
    text-decoration: underline;
}

.seup-company-info {
    background: linear-gradient(135deg, var(--primary-50), var(--primary-100));
    border: 1px solid var(--primary-200);
    border-radius: var(--radius-lg);
    padding: var(--space-6);
    margin-bottom: var(--space-4);
}

.seup-company-info h4 {
    margin: 0 0 var(--space-4) 0;
    color: var(--primary-800);
    font-size: var(--text-xl);
    font-weight: var(--font-bold);
}

.seup-contact-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: var(--space-3);
}

.seup-contact-item {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    color: var(--primary-700);
    font-weight: var(--font-medium);
}

.seup-contact-item i {
    width: 20px;
    text-align: center;
    color: var(--primary-600);
}

.seup-contact-item a {
    color: var(--primary-700);
    text-decoration: none;
}

.seup-contact-item a:hover {
    color: var(--primary-800);
    text-decoration: underline;
}

.seup-legal-notice {
    background: var(--warning-50);
    border: 1px solid var(--warning-200);
    border-radius: var(--radius-lg);
    padding: var(--space-6);
}

.seup-legal-notice h4 {
    margin: 0 0 var(--space-4) 0;
    color: var(--warning-800);
    font-size: var(--text-lg);
    font-weight: var(--font-semibold);
}

.seup-legal-content p {
    margin: 0 0 var(--space-3) 0;
    color: var(--warning-800);
    line-height: var(--leading-relaxed);
}

.seup-legal-content ul {
    margin: 0 0 var(--space-4) var(--space-4);
    color: var(--warning-800);
}

.seup-legal-content li {
    margin-bottom: var(--space-1);
}

.seup-legal-reference {
    font-size: var(--text-sm);
    font-style: italic;
    background: var(--warning-100);
    padding: var(--space-3);
    border-radius: var(--radius-md);
    border-left: 4px solid var(--warning-500);
}

.seup-legal-penalty {
    font-size: var(--text-sm);
    font-weight: var(--font-semibold);
    background: var(--error-100);
    padding: var(--space-3);
    border-radius: var(--radius-md);
    border-left: 4px solid var(--error-500);
    color: var(--error-800);
}

.seup-support-cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: var(--space-4);
}

.seup-support-card {
    background: var(--neutral-50);
    border: 1px solid var(--neutral-200);
    border-radius: var(--radius-lg);
    padding: var(--space-6);
    text-align: center;
    transition: all var(--transition-normal);
}

.seup-support-card:hover {
    transform: translateY(-4px);
    box-shadow: var(--shadow-lg);
    border-color: var(--primary-200);
}

.seup-support-icon {
    width: 64px;
    height: 64px;
    background: linear-gradient(135deg, var(--success-500), var(--success-600));
    border-radius: var(--radius-xl);
    display: flex;
    align-items: center;
    justify-content: center;
    color: white;
    font-size: 24px;
    margin: 0 auto var(--space-4) auto;
}

.seup-support-card h4 {
    margin: 0 0 var(--space-2) 0;
    font-size: var(--text-lg);
    font-weight: var(--font-semibold);
    color: var(--secondary-900);
}

.seup-support-card p {
    margin: 0 0 var(--space-4) 0;
    color: var(--secondary-600);
    line-height: var(--leading-relaxed);
}

.seup-support-btn {
    display: inline-flex;
    align-items: center;
    padding: var(--space-3) var(--space-6);
    background: linear-gradient(135deg, var(--success-500), var(--success-600));
    color: white;
    text-decoration: none;
    border-radius: var(--radius-lg);
    font-weight: var(--font-medium);
    transition: all var(--transition-normal);
    box-shadow: var(--shadow-md);
}

.seup-support-btn:hover {
    background: linear-gradient(135deg, var(--success-600), var(--success-700));
    transform: translateY(-2px);
    box-shadow: var(--shadow-lg);
    color: white;
    text-decoration: none;
}

/* Responsive design */
@media (max-width: 768px) {
    .seup-info-grid {
        grid-template-columns: repeat(2, 1fr);
    }
    
    .seup-features-grid {
        grid-template-columns: 1fr;
    }
    
    .seup-authors {
        grid-template-columns: 1fr;
    }
    
    .seup-contact-grid {
        grid-template-columns: repeat(2, 1fr);
    }
    
    .seup-support-cards {
        grid-template-columns: 1fr;
    }
}

@media (max-width: 480px) {
    .seup-info-grid {
        grid-template-columns: 1fr;
    }
    
    .seup-contact-grid {
        grid-template-columns: 1fr;
    }
}
</style>';

// Page end
print dol_get_fiche_end();
llxFooter();
$db->close();
