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
 *	\file       seup/tagovi.php
 *	\ingroup    seup
 *	\brief      Tagovi page
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

require_once DOL_DOCUMENT_ROOT . '/core/class/html.formfile.class.php';

// Učitaj datoteke prijevoda
$langs->loadLangs(array("seup@seup"));

$action = GETPOST('action', 'aZ09');
$now = dol_now();

// Sigurnosna provjera
$socid = GETPOST('socid', 'int');
if (isset($user->socid) && $user->socid > 0) {
    $action = '';
    $socid = $user->socid;
}

// Process form submission
$error = 0;
$success = 0;
$tag_name = '';

// Ensure database tables exist
require_once __DIR__ . '/../class/predmet_helper.class.php';
Predmet_helper::createSeupDatabaseTables($db);

if ($action == 'addtag' && !empty($_POST['tag'])) {
    $tag_name = GETPOST('tag', 'alphanohtml');
    $tag_color = GETPOST('tag_color', 'alpha');

    // Validate input
    if (dol_strlen($tag_name) < 2) {
        $error++;
        setEventMessages($langs->trans('ErrorTagTooShort'), null, 'errors');
    } else {
        $db->begin();

        // Check if tag already exists
        $sql = "SELECT rowid FROM " . MAIN_DB_PREFIX . "a_tagovi
                WHERE tag = '" . $db->escape($tag_name) . "'
                AND entity = " . $conf->entity;

        $resql = $db->query($sql);
        if ($resql) {
            if ($db->num_rows($resql) > 0) {
                $error++;
                setEventMessages($langs->trans('ErrorTagAlreadyExists'), null, 'errors');
            } else {
                // Insert new tag with color
                $sql = "INSERT INTO " . MAIN_DB_PREFIX . "a_tagovi 
                        (tag, color, entity, date_creation, fk_user_creat) 
                        VALUES (
                            '" . $db->escape($tag_name) . "',
                            '" . $db->escape($tag_color) . "',
                            " . $conf->entity . ",
                            '" . $db->idate(dol_now()) . "',
                            " . $user->id . "
                        )";

                $resql = $db->query($sql);
                if ($resql) {
                    $db->commit();
                    $success++;
                    $tag_name = ''; // Reset input field
                    setEventMessages($langs->trans('TagAddedSuccessfully'), null, 'mesgs');
                } else {
                    $db->rollback();
                    $error++;
                    setEventMessages($langs->trans('ErrorTagNotAdded') . ' ' . $db->lasterror(), null, 'errors');
                }
            }
        } else {
            $db->rollback();
            $error++;
            setEventMessages($langs->trans('ErrorDatabaseRequest') . ' ' . $db->lasterror(), null, 'errors');
        }
    }
}

if ($action == 'deletetag') {
    $tagid = GETPOST('tagid', 'int');
    if ($tagid > 0) {
        $db->begin();

        // First delete associations in a_predmet_tagovi
        $sql = "DELETE FROM " . MAIN_DB_PREFIX . "a_predmet_tagovi
                WHERE fk_tag = " . $tagid;
        $resql = $db->query($sql);

        if ($resql) {
            // Then delete the tag itself
            $sql = "DELETE FROM " . MAIN_DB_PREFIX . "a_tagovi
                    WHERE rowid = " . $tagid . "
                    AND entity = " . $conf->entity;

            $resql = $db->query($sql);
            if ($resql) {
                $db->commit();
                setEventMessages($langs->trans('TagDeletedSuccessfully'), null, 'mesgs');
            } else {
                $db->rollback();
                setEventMessages($langs->trans('ErrorTagNotDeleted') . ' ' . $db->lasterror(), null, 'errors');
            }
        } else {
            $db->rollback();
            setEventMessages($langs->trans('ErrorDeletingTagAssociations') . ' ' . $db->lasterror(), null, 'errors');
        }
    }
}

/*
 * View
 */

$form = new Form($db);
$formfile = new FormFile($db);

// Set page title to "Tagovi"
llxHeader("", $langs->trans("Tagovi"), '', '', 0, 0, '', '', '', 'mod-seup page-tagovi');

// Modern design assets
print '<meta name="viewport" content="width=device-width, initial-scale=1">';
print '<link rel="preconnect" href="https://fonts.googleapis.com">';
print '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>';
print '<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">';
print '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">';
print '<link href="/custom/seup/css/seup-modern.css" rel="stylesheet">';
print '<link href="/custom/seup/css/tagovi.css" rel="stylesheet">';

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
print '<h1 class="seup-settings-title">Upravljanje Oznakama</h1>';
print '<p class="seup-settings-subtitle">Kreirajte i organizirajte oznake za kategorizaciju predmeta i dokumenata</p>';
print '</div>';

// Main content container
print '<div class="seup-tagovi-container">';

// Add Tag Form
print '<div class="seup-tag-form animate-fade-in-up">';
print '<form method="POST" action="" id="tagForm">';
print '<input type="hidden" name="action" value="addtag">';
print '<div class="seup-tag-form-grid">';

print '<div class="seup-tag-input-group">';
print '<label for="tag" class="seup-label"><i class="fas fa-tag me-2"></i>' . $langs->trans('Tag') . '</label>';
print '<input type="text" name="tag" id="tag" class="seup-tag-input" ';
print 'placeholder="' . $langs->trans('UnesiNoviTag') . '" ';
print 'value="' . $tag_name . '" required maxlength="50">';
print '<div class="seup-help-text"><i class="fas fa-info-circle"></i> ' . $langs->trans('TagoviHelpText') . '</div>';

// Color Picker
print '<div class="seup-color-picker">';
print '<div class="seup-color-picker-label"><i class="fas fa-palette me-2"></i>Odaberite boju</div>';
print '<div class="seup-color-options">';

$colors = [
    'red' => '#ef4444',
    'blue' => '#3b82f6', 
    'green' => '#22c55e',
    'purple' => '#a855f7',
    'orange' => '#f97316',
    'pink' => '#ec4899'
];

foreach ($colors as $colorName => $colorValue) {
    $checked = ($colorName === 'blue') ? 'checked' : '';
    print '<label class="seup-color-option seup-color-' . $colorName . ($checked ? ' selected' : '') . '">';
    print '<input type="radio" name="tag_color" value="' . $colorName . '" class="seup-color-input" ' . $checked . '>';
    print '</label>';
}

print '</div>';
print '</div>';
print '</div>';

print '<div style="display: flex; align-items: end;">';
print '<button type="submit" class="seup-btn seup-btn-primary" id="addTagBtn">';
print '<i class="fas fa-plus me-2"></i>' . $langs->trans('DodajTag');
print '</button>';
print '</div>';

print '</div>'; // seup-tag-form-grid
print '</form>';
print '</div>';

// Tags List
print '<div class="seup-tags-list animate-fade-in-up">';

// Fetch existing tags with colors
$sql = "SELECT rowid, tag, color, date_creation
        FROM " . MAIN_DB_PREFIX . "a_tagovi
        WHERE entity = " . $conf->entity . "
        ORDER BY tag ASC";

$resql = $db->query($sql);
$tags = [];
if ($resql) {
    while ($obj = $db->fetch_object($resql)) {
        $tags[] = $obj;
    }
} else {
    dol_syslog("Error fetching tags: " . $db->lasterror(), LOG_ERR);
    setEventMessages("Greška pri dohvaćanju oznaka: " . $db->lasterror(), null, 'errors');
}

// Header with stats
print '<div class="seup-tags-header">';
print '<div>';
print '<h4 class="seup-tags-title">';
print '<i class="fas fa-tags"></i>' . $langs->trans('ExistingTags');
print '</h4>';
print '<div class="seup-tags-stats">';
print '<div class="seup-stat-item">';
print '<i class="fas fa-hashtag"></i>';
print '<span>Ukupno: <span class="seup-stat-number">' . count($tags) . '</span></span>';
print '</div>';
foreach ($colors as $colorName => $colorValue) {
    $colorCount = count(array_filter($tags, function($tag) use ($colorName) {
        return $tag->color === $colorName;
    }));
    if ($colorCount > 0) {
        print '<div class="seup-stat-item">';
        print '<div class="seup-color-filter-btn seup-color-' . $colorName . '" style="width: 16px; height: 16px;"></div>';
        print '<span>' . $colorCount . '</span>';
        print '</div>';
    }
}
print '</div>';
print '</div>';

// Search and filter controls
print '<div class="seup-color-filter">';
print '<span style="font-size: var(--text-sm); color: rgba(255, 255, 255, 0.9); margin-right: var(--space-2);">Filter:</span>';
print '<div class="seup-color-filter-btn all active" data-color="all" title="Sve boje"></div>';
foreach ($colors as $colorName => $colorValue) {
    print '<div class="seup-color-filter-btn seup-color-' . $colorName . '" data-color="' . $colorName . '" title="' . ucfirst($colorName) . '"></div>';
}
print '</div>';
print '</div>';

// Search controls
print '<div class="seup-tags-controls">';
print '<div class="seup-search-container">';
print '<div class="seup-search-input-wrapper">';
print '<i class="fas fa-search seup-search-icon"></i>';
print '<input type="text" id="searchInput" class="seup-search-input" placeholder="Pretraži oznake...">';
print '</div>';
print '</div>';
print '</div>';

// Tags grid
if (count($tags) > 0) {
    print '<div class="seup-tags-grid" id="tagsGrid">';
    
    foreach ($tags as $tag) {
        $colorClass = $tag->color ?: 'blue';
        print '<div class="seup-tag-item" data-color="' . $colorClass . '" data-tag="' . strtolower($tag->tag) . '">';
        
        print '<div class="seup-tag-content">';
        print '<div class="seup-tag-color-indicator"></div>';
        print '<span class="seup-tag-text">' . htmlspecialchars($tag->tag) . '</span>';
        print '</div>';
        
        print '<div class="seup-tag-actions">';
        print '<form method="POST" action="" style="display:inline;">';
        print '<input type="hidden" name="action" value="deletetag">';
        print '<input type="hidden" name="tagid" value="' . $tag->rowid . '">';
        print '<button type="submit" class="seup-tag-delete-btn" ';
        print 'onclick="return confirm(\'' . dol_escape_js($langs->trans('ConfirmDeleteTag')) . '\')" ';
        print 'title="Obriši oznaku">';
        print '<i class="fas fa-trash"></i>';
        print '</button>';
        print '</form>';
        print '</div>';
        
        print '</div>';
    }
    
    print '</div>';
} else {
    print '<div class="seup-tags-empty">';
    print '<i class="fas fa-tags seup-empty-icon"></i>';
    print '<h4 class="seup-empty-title">' . $langs->trans('NoTagsAvailable') . '</h4>';
    print '<p class="seup-empty-description">Dodajte prvu oznaku za početak organizacije</p>';
    print '</div>';
}

print '</div>'; // seup-tags-list

print '</div>'; // seup-tagovi-container
print '</div>'; // seup-settings-content
print '</main>';

// JavaScript for enhanced functionality
print '<script src="/custom/seup/js/seup-modern.js"></script>';

?>

<script>
document.addEventListener('DOMContentLoaded', function() {
    // Color picker functionality
    const colorOptions = document.querySelectorAll('.seup-color-option');
    const colorInputs = document.querySelectorAll('.seup-color-input');

    colorOptions.forEach(option => {
        option.addEventListener('click', function() {
            // Remove selected class from all options
            colorOptions.forEach(opt => opt.classList.remove('selected'));
            
            // Add selected class to clicked option
            this.classList.add('selected');
            
            // Check the corresponding radio input
            const input = this.querySelector('.seup-color-input');
            if (input) {
                input.checked = true;
            }
        });
    });

    // Search functionality
    const searchInput = document.getElementById('searchInput');
    const tagItems = document.querySelectorAll('.seup-tag-item');

    if (searchInput) {
        searchInput.addEventListener('input', function() {
            const searchTerm = this.value.toLowerCase();
            let visibleCount = 0;

            tagItems.forEach(item => {
                const tagText = item.dataset.tag;
                if (tagText.includes(searchTerm)) {
                    item.style.display = '';
                    visibleCount++;
                } else {
                    item.style.display = 'none';
                }
            });

            // Update count in header
            const countElement = document.querySelector('.seup-stat-number');
            if (countElement) {
                countElement.textContent = visibleCount;
            }
        });
    }

    // Color filter functionality
    const colorFilterBtns = document.querySelectorAll('.seup-color-filter-btn');
    
    colorFilterBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const filterColor = this.dataset.color;
            
            // Remove active class from all filter buttons
            colorFilterBtns.forEach(b => b.classList.remove('active'));
            
            // Add active class to clicked button
            this.classList.add('active');
            
            // Filter tags
            let visibleCount = 0;
            tagItems.forEach(item => {
                const itemColor = item.dataset.color;
                
                if (filterColor === 'all' || itemColor === filterColor) {
                    item.style.display = '';
                    visibleCount++;
                } else {
                    item.style.display = 'none';
                }
            });

            // Update count
            const countElement = document.querySelector('.seup-stat-number');
            if (countElement) {
                countElement.textContent = visibleCount;
            }
        });
    });

    // Form submission with loading state
    const tagForm = document.getElementById('tagForm');
    const addTagBtn = document.getElementById('addTagBtn');
    const tagInput = document.getElementById('tag');

    if (tagForm && addTagBtn) {
        tagForm.addEventListener('submit', function(e) {
            const tagValue = tagInput.value.trim();
            
            if (tagValue.length < 2) {
                e.preventDefault();
                tagInput.classList.add('error');
                showMessage('Oznaka mora imati najmanje 2 znaka', 'error');
                return;
            }

            // Add loading state
            addTagBtn.classList.add('seup-loading');
            tagInput.classList.remove('error');
            tagInput.classList.add('success');
        });
    }

    // Input validation
    if (tagInput) {
        tagInput.addEventListener('input', function() {
            this.classList.remove('error', 'success');
            
            if (this.value.length >= 2) {
                this.classList.add('success');
            }
        });
    }

    // Delete button loading states
    document.querySelectorAll('.seup-tag-delete-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            if (confirm('<?php echo dol_escape_js($langs->trans('ConfirmDeleteTag')); ?>')) {
                this.classList.add('seup-loading');
            }
        });
    });

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

    // Add staggered animation to existing tags
    tagItems.forEach((item, index) => {
        item.style.animationDelay = `${index * 100}ms`;
        item.classList.add('new-tag');
    });
});
</script>

<?php
llxFooter();
$db->close();
?>