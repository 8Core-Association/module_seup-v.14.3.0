<?php
// Plaćena licenca – (c) 2025 Tomislav Galić <tomislav@8core.hr>

require '../../main.inc.php'; // Adjust path if needed
require_once DOL_DOCUMENT_ROOT.'/ecm/class/ecmfiles.class.php';
require_once DOL_DOCUMENT_ROOT.'/custom/seup/vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

// Konfiguracija
$secret = 'UBSIuw2R7ZoCzZVlfqtLIMRvrKMQX5pt'; // JWT tajni ključ
$content = file_get_contents("php://input");
$data = json_decode($content, true);

// Log (ako trebaš debugiranje)
//file_put_contents('/tmp/onlyoffice_callback.log', $content . PHP_EOL, FILE_APPEND);

// Provjeri status dokumenta
if (!isset($data['status'])) {
    http_response_code(400);
    echo json_encode(['error' => 'Nema statusa']);
    exit;
}

$status = (int) $data['status'];

// Samo ako je dokument uspješno spremljen (status 2 = spremanje završeno, 6 = spremanje + zatvoreno)
if (in_array($status, [2, 6]) && isset($data['url'])) {
    $newfileurl = $data['url'];
    $key = $data['key'] ?? '';

    // Ovdje možeš napraviti dohvat ecmfile_id po nekom internom mapiranju
    // U ovom primjeru: pretpostavljamo da postoji dolazak s $_GET['ecmfile_id']
    $ecmfile_id = (int) ($_GET['ecmfile_id'] ?? 0);
    if ($ecmfile_id <= 0) {
        http_response_code(400);
        echo json_encode(['error' => 'Nedostaje ecmfile_id']);
        exit;
    }

    // Spremi novi sadržaj u filesystem (Dolibarr koristi fizičke fajlove)
    $ecmfile = new EcmFiles($db);
    if ($ecmfile->fetch($ecmfile_id) > 0) {
        $localfile = $ecmfile->getFullPath();
        $newcontent = @file_get_contents($newfileurl);
        if ($newcontent !== false) {
            file_put_contents($localfile, $newcontent);
            echo json_encode(['result' => 'OK']);
            exit;
        }
    }

    http_response_code(500);
    echo json_encode(['error' => 'Nije moguće spremiti novi sadržaj']);
    exit;
}

// Ostali statusi – ignoriraj, ali vrati OK
echo json_encode(['result' => 'OK']);
exit;
