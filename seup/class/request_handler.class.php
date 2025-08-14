<?php

require_once '../../../main.inc.php';


class Request_Handler
{
  public static function handleOtvoriPredmet($db, $conf, $user)
  {
    while (ob_get_level() > 0) {
      ob_end_clean();
    }
    dol_syslog('POST request za otvaranje predmeta', LOG_INFO);
    header('Content-Type: application/json; charset=utf-8');

    global $langs;

    $db->begin();

    try {
      $klasa_br = GETPOST('klasa_br', 'alphanohtml');
      $sadrzaj = GETPOST('sadrzaj', 'alphanohtml');
      $dosje_br = GETPOST('dosje_broj', 'int');
      $god = GETPOST('god', 'int');
      $naziv = GETPOST('naziv', 'alphanohtml');
      $id_zaposlenik = GETPOST('zaposlenik', 'int');
      $stranka = GETPOST('stranka', 'alphanohtml');
      $datum_otvaranja = null;

      // Jer dolibarr nije normalan pa ak ima samo jedan tag, on ga vrati kao string, a ne array. bozpomoz
      $tags = GETPOST('tags', 'array') ?: [];
      if (is_string($tags)) {
        $tags = [$tags]; // Convert single value to array
      }

      if (!empty($_POST['datumOtvaranja'])) {
        $datum_otvaranja = GETPOST('datumOtvaranja', 'alphanohtml') ?: date('Y-m-d H:i:s');
        dol_syslog("Datum otvaranja predmeta: " . $datum_otvaranja, LOG_INFO);
      }

      // Convert empty string to null
      $stranka = empty($stranka) ? null : $stranka;

      $requiredFields = [
        'klasa_br' => $klasa_br,
        'sadrzaj' => $sadrzaj,
        'dosje_broj' => $dosje_br,
        'god' => $god,
        'naziv' => $naziv,
        'zaposlenik' => $id_zaposlenik
      ];

      $missingFields = [];
      foreach ($requiredFields as $field => $value) {
        if (empty($value)) {
          $missingFields[] = $field;
        }
      }

      if (count($missingFields) > 0) {
        throw new Exception("Obavezna polja nisu popunjena: " . implode(', ', $missingFields));
      }

      $ustanova_info = Predmet_helper::getUstanovaByZaposlenik($db, $id_zaposlenik);
      if (!$ustanova_info) {
        throw new Exception("Zaposlenik nije pronađen ili nema povezanu ustanovu");
      }
      $id_ustanove = $ustanova_info->ID_ustanove;

      $klasifikacija = Predmet_helper::getKlasifikacijskaOznaka($db, $klasa_br, $sadrzaj, $dosje_br);
      if (!$klasifikacija) {
        throw new Exception("Klasifikacijska oznaka nije pronađena");
      }

      $id_klasifikacijske_oznake = $klasifikacija->ID_klasifikacijske_oznake;
      $vrijeme_cuvanja = $klasifikacija->vrijeme_cuvanja;

      $rbr_predmeta = Predmet_helper::getNextPredmetRbr($db, $klasa_br, $sadrzaj, $dosje_br, $god);
      if ($rbr_predmeta === false) {
        throw new Exception("Neuspješno dobivanje sljedećeg rednog broja predmeta");
      }
      dol_syslog("Stranka za insert: " . $stranka, LOG_INFO);

      $soc_id = null;
      if (!empty($stranka)) {
        // Validate and get societe ID
        $sql = "SELECT rowid FROM " . MAIN_DB_PREFIX . "societe 
                    WHERE nom = '" . $db->escape($stranka) . "' 
                    OR tva_intra = '" . $db->escape($stranka) . "' 
                    LIMIT 1";
        $res = $db->query($sql);
        if ($res && $obj = $db->fetch_object($res)) {
          $soc_id = (int)$obj->rowid;
        } else {
          throw new Exception("Stranka not found: " . $stranka);
        }
      }
      $db_query = Predmet_helper::insertPredmet(
        $db,
        $klasa_br,
        $sadrzaj,
        $dosje_br,
        $god,
        $rbr_predmeta,
        $naziv,
        $id_ustanove,
        $id_zaposlenik,
        $id_klasifikacijske_oznake,
        $vrijeme_cuvanja
      );

      if ($db_query === false) {
        throw new Exception("Failed to insert case: " . $db->lasterror());
      }

      // Get the ID of the newly created case
      $predmet_id = $db->last_insert_id(MAIN_DB_PREFIX . 'a_predmet', 'ID_predmeta');
      if (!$predmet_id) {
        throw new Exception("Failed to get new case ID: " . $db->lasterror());
      }

      // Create predmet directory with new naming structure
      $created_path = Predmet_helper::createPredmetDirectory($predmet_id, $db, $conf);
      if (!$created_path) {
        throw new Exception("Failed to create predmet directory");
      }

      // Insert tag associations if tags are selected
      if (!empty($tags) && is_array($tags)) {
        foreach ($tags as $tag_id) {
          $tag_id = (int)$tag_id;
          if ($tag_id > 0) {
            $sql = "INSERT INTO " . MAIN_DB_PREFIX . "a_predmet_tagovi 
                            (fk_predmet, fk_tag) 
                            VALUES (" . (int)$predmet_id . ", " . $tag_id . ")";
            $res = $db->query($sql);
            if (!$res) {
              throw new Exception("Error adding tag: " . $db->lasterror());
            }
          }
        }
      }
      dol_syslog("Tags received: " . print_r($tags, true), LOG_DEBUG);

      if ($soc_id) {
        $sql = "INSERT INTO " . MAIN_DB_PREFIX . "a_predmet_stranka (
                    ID_predmeta, 
                    fk_soc, 
                    role
                ) VALUES (
                    " . ((int)$predmet_id) . ",
                    " . ((int)$soc_id) . ",
                    'creator'
                )";

        $res = $db->query($sql);
        if (!$res) {
          throw new Exception("Failed to insert stranka: " . $db->lasterror());
        }
      }

      $db->commit();

      // Return success response
      //header('Content-Type: application/json; charset=utf-8');
      echo json_encode([
        'success' => true,
        'message' => $langs->trans('CaseCreatedSuccessfully'),
        'predmet_id' => $predmet_id
      ]);
      exit;
    } catch (Exception $e) {
      $db->rollback();
      dol_syslog("Error during case creation: " . $e->getMessage(), LOG_ERR);

      http_response_code(400);
      echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
      ]);
      exit;
    }
  }


  public static function handleUploadDocument($db, $upload_dir, $langs, $conf, $user)
  {
    // Uzmi podatke o ID-u predmeta iz POST zahtjeva
    $caseId = GETPOST('case_id', 'int');
    
    // Use the new folder structure
    $relative_path = Predmet_helper::getPredmetFolderPath($caseId, $db);
    $predmet_dir = DOL_DATA_ROOT . '/ecm/' . $relative_path;
    
    if (!is_dir($predmet_dir)) {
      dol_mkdir($predmet_dir);
    }
    dol_syslog("predmet_dir: " . $predmet_dir, LOG_INFO);
    $allowed_mimes = [
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document' => 'docx',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' => 'xlsx',
      'application/vnd.google-apps.document' => 'docx', // Google Docs native MIME (API)
      'application/octet-stream' => 'docx',             // Fallback from some browsers
      'application/zip' => 'docx',                      // Often used on Linux

      'application/pdf' => 'pdf',
      'image/jpeg' => 'jpg',
      'image/png' => 'png',

      'application/msword' => 'doc', // Za starije Word dokumente
      'application/vnd.ms-excel' => 'xls', // Za starije Excel dokumente
      'application/vnd.oasis.opendocument.text' => 'odt' // LibreOffice, OpenOffice dokumenti
    ];

    try {
      $ecmfile = new EcmFiles($db);
      // Create directory if needed
      if (!is_dir($predmet_dir)) {
        dol_syslog("Creating directory: " . $predmet_dir, LOG_INFO);
        if (!dol_mkdir($predmet_dir)) {
          throw new Exception($langs->trans("ErrorCantCreateDir"));
        }
      }

      $file = $_FILES['document'];
      if (!isset($file['tmp_name']) || !is_uploaded_file($file['tmp_name'])) {
        throw new Exception($langs->trans("ErrorFileNotUploaded"));
      }

      $finfo = new finfo(FILEINFO_MIME_TYPE);

      $mime = $finfo->file($file['tmp_name']);
      // Clean the MIME type string
      $mime = preg_replace('/application\/.*?(application\/.*)/', '$1', $mime); // Makni duplikat mime stringa (nesto server zajebava pa ga vraca duplog boga pitaj zast)
      $mime = explode(';', $mime)[0]; // Remove charset/encoding
      $mime = trim($mime);

      $ext = pathinfo($file['name'], PATHINFO_EXTENSION);

      dol_syslog("Filename extension: " . $ext, LOG_INFO);
      dol_syslog("Cleaned MIME type: " . $mime, LOG_INFO);

      if (!isset($allowed_mimes[$mime])) {
        throw new Exception("Nevalja file type: " . $mime);
      }

      // Sigurnosna provjera formata - (sprjecava da se preimenovani zip ili exe file potencionalno zlonamjeran moze uploadati)
      $file_header = file_get_contents($file['tmp_name'], false, null, 0, 8);
      $allowed_headers = [
        // ZIP-based formats (must be at start)
        ["\x50\x4B\x03\x04", 4, 0],      // Standard ZIP (DOCX/XLSX)
        ["\x50\x4B\x05\x06", 4, 0],      // Empty ZIP
        ["\x50\x4B\x07\x08", 4, 0],      // Spanned ZIP

        // Other formats (must be at start)
        ["\x25\x50\x44\x46", 4, 0],      // PDF
        ["\xFF\xD8\xFF", 3, 0],           // JPEG
        ["\x89\x50\x4E\x47\x0D\x0A\x1A\x0A", 8, 0], // PNG
        ["\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", 8, 0], // Stari Word/XLS

        // Google Docs (anywhere in first 8 bytes)
        ["\x47\x6F\x6F\x67\x6C\x65", 6, null] // "Google"
      ];

      $valid = false;
      foreach ($allowed_headers as $header) {
        [$signature, $length, $position] = $header;

        if ($position !== null) {
          // Check at specific position using strncmp()
          if (strncmp(substr($file_header, $position, $length), $signature, $length) === 0) {
            $valid = true;
            break;
          }
        } else {
          // Check anywhere in header using strpos()
          if (strpos($file_header, $signature) !== false) {
            $valid = true;
            break;
          }
        }
      }


      if (!$valid) {
        throw new Exception("Invalid file signature");
      }

      // Sanitize filename
      $filename = preg_replace('/[^a-zA-Z0-9-_\.]/', '', basename($file['name']));
      $filename = substr($filename, 0, 255);  // Limit filename length

      // Move uploaded file
      $fullpath = $predmet_dir . $filename;
      if (!move_uploaded_file($file['tmp_name'], $fullpath)) {
        throw new Exception($langs->trans("ErrorMovingUploadedFile"));
      }

      // Create ECM record in database
      $ecmfile = new EcmFiles($db);
      
      // Debug: Log the paths being used
      dol_syslog("handleUploadDocument: relative_path = " . $relative_path . " (length: " . strlen($relative_path) . ")", LOG_INFO);
      dol_syslog("handleUploadDocument: predmet_dir = " . $predmet_dir, LOG_INFO);
      dol_syslog("handleUploadDocument: filename = " . $filename, LOG_INFO);
      
      // Ensure filepath doesn't end with slash for ECM compatibility
      $ecm_filepath = rtrim($relative_path, '/');
      dol_syslog("handleUploadDocument: ecm_filepath = " . $ecm_filepath . " (length: " . strlen($ecm_filepath) . ")", LOG_INFO);
      
      $ecmfile->filepath = $ecm_filepath;
      $ecmfile->filename = $filename;
      $ecmfile->label = $filename;
      $ecmfile->entity = $conf->entity;
      $ecmfile->gen_or_uploaded = 'uploaded';
      $ecmfile->description = 'Document for predmet ' . $caseId;
      $ecmfile->fk_user_c = $user->id;
      $ecmfile->fk_user_m = $user->id;
      $ecmfile->date_c = dol_now();
      $ecmfile->date_m = dol_now();
      
      // Create the ECM record
      $result = $ecmfile->create($user);
      if ($result < 0) {
        dol_syslog("handleUploadDocument: ECM creation failed - " . $ecmfile->error, LOG_ERR);
        throw new Exception("ECM creation failed: " . $ecmfile->error);
      }
      
      dol_syslog("handleUploadDocument: ECM record created successfully for file: " . $filename . " with filepath: " . $relative_path, LOG_INFO);

      setEventMessages($langs->trans("FileUploadSuccess"), null, 'mesgs');
    } catch (Exception $e) {
      setEventMessages($e->getMessage(), null, 'errors');
    }
  }

  public static function handleCheckPredmetExists($db)
  {
    header('Content-Type: application/json; charset=utf-8');
    ob_end_clean();  // Ocisti cijeli buffer da ne remeti json requestove

    try {
      // Uzmi podatke iz AJAX requesta
      $klasa_br = trim(GETPOST('klasa_br', 'alphanohtml'));
      $sadrzaj = trim(GETPOST('sadrzaj', 'alphanohtml'));
      $dosje_br = trim(GETPOST('dosje_br', 'alphanohtml'));
      $god = trim(GETPOST('god', 'alphanohtml'));

      dol_syslog('AJAX request za provjeru predmeta', LOG_INFO);

      if (Predmet_helper::checkPredmetExists($db, $klasa_br, $sadrzaj, $dosje_br, $god)) {
        // nadi najveci rbr predmeta, dodaj 1 i prikazi ga na ekranu u klasi
        $nextRbr = Predmet_helper::getNextPredmetRbr($db, $klasa_br, $sadrzaj, $dosje_br, $god);
        dol_syslog("Predmet postoji, sljedeci redni broj je: " . $nextRbr, LOG_INFO);
        // response predmet s novim rednim brojem :) 
        echo json_encode(['status' => 'exists', 'next_rbr' => $nextRbr]);
      } else {
        dol_syslog("Predmet ne postoji", LOG_INFO);

        echo json_encode(['status' => 'new', 'next_rbr' => 1]);
      }
    } catch (Exception $e) {
      // Catch any exceptions and return an error response
      dol_syslog("Error during AJAX processing: " . $e->getMessage(), LOG_ERR);
      echo json_encode(['status' => 'error', 'message' => $e->getMessage()]);
    }
  }

  public static function handleStrankaAutocomplete($db)
  {
    ob_end_clean();  // Ocisti cijeli buffer
    $term = GETPOST('term', 'alphanohtml');
    if (empty($term)) {
      echo json_encode([]);
      return;
    }

    $results = [];

    // Check if input is numeric (search by VAT)
    if (is_numeric($term)) {
      $sql = "SELECT rowid, nom AS label, tva_intra AS vat 
                FROM " . MAIN_DB_PREFIX . "societe 
                WHERE tva_intra LIKE '%" . $db->escape($term) . "%' 
                AND entity IN (" . getEntity('societe') . ") 
                ORDER BY nom ASC 
                LIMIT 10";
    }
    // Search by name for text input
    else {
      $sql = "SELECT rowid, nom AS label, tva_intra AS vat 
                FROM " . MAIN_DB_PREFIX . "societe 
                WHERE nom LIKE '%" . $db->escape($term) . "%' 
                AND entity IN (" . getEntity('societe') . ") 
                ORDER BY nom ASC 
                LIMIT 10";
    }

    $resql = $db->query($sql);
    if ($resql) {
      while ($obj = $db->fetch_object($resql)) {
        $results[] = [
          'label' => $obj->label,
          'vat' => $obj->vat
        ];
      }
    }

    header('Content-Type: application/json');
    echo json_encode($results);
    exit;
  }
}