<?php
require '../../main.inc.php';

$data = json_decode(file_get_contents('php://input'), true);

if ($data['status'] == 2) { // Dokument spremljen
    $file_url = $data['url'];
    $file_content = file_get_contents($file_url);
    
    // Ažuriraj dokument u SEUP
    $result = $db->query("UPDATE ".MAIN_DB_PREFIX."seup_documents 
                          SET content = '".$db->escape($file_content)."'
                          WHERE ref = '".$db->escape($data['key'])."'");
}