<?php

require_once __DIR__ . '/../../../conf/conf.php';
require_once __DIR__ . '/../../../main.inc.php';


header('Content-Type: application/json');
if (isset($_POST['query'])) {
    $search = GETPOST('query', 'alphanohtml');
    $search = $db->escape("%$search");
    
    $sql = "SELECT 
            ID_klasifikacijske_oznake,
            klasa_broj,
            sadrzaj,
            dosje_broj,
            vrijeme_cuvanja,
            opis_klasifikacijske_oznake
        FROM " . MAIN_DB_PREFIX . "a_klasifikacijska_oznaka 
        WHERE klasa_broj LIKE '".$search."%'";
    
    $resql = $db->query($sql);
    $results = [];
    // NE ZABORAVI da objekt ima iste nazive kao i stupci u bazi!!!
    if ($resql && $db->num_rows($resql) > 0) {
        while ($obj = $db->fetch_object($resql)) {
            
            $results[] = [
                'klasa_br' => $obj->klasa_broj,
                'sadrzaj' => $obj->sadrzaj,
                'dosje_br' => $obj->dosje_broj,
                'vrijeme_cuvanja' => $obj->vrijeme_cuvanja,
                'opis_klasifikacije' => $obj->opis_klasifikacijske_oznake,
                'ID' => $obj->ID_klasifikacijske_oznake
            ];
        }
    }
    dol_syslog("Rezultat[] : " . json_encode($results, JSON_PRETTY_PRINT), LOG_INFO);

    echo json_encode($results);
    exit;
}