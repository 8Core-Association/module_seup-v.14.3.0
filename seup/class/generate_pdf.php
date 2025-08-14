<?php
/*
require_once '../../../main.inc.php';
require_once DOL_DOCUMENT_ROOT . '/core/lib/files.lib.php';
require_once DOL_DOCUMENT_ROOT . '/core/lib/pdf.lib.php';
ob_end_clean();
// Load language files
$langs->load("main");
$langs->load("errors");

// Create PDF instance
$pdf = pdf_getInstance();
$pdf->SetFont(pdf_getPDFFont($langs), '', 12);
$pdf->Open();
$pdf->AddPage();

// Add sample content instead of blank page
$pdf->SetFont('', 'B', 16);
$pdf->Cell(0, 10, $langs->trans("SampleDocument"), 0, 1, 'C');
$pdf->SetFont('', '', 12);
$pdf->MultiCell(0, 10, $langs->trans("ThisIsASamplePDFDocumentGeneratedByDolibarr"), 0, 'L');

// 1. Use proper Dolibarr temp directory
$tmpdir = DOL_DATA_ROOT . '/temp';
if (!is_dir($tmpdir)) {
    if (!dol_mkdir($tmpdir)) {
        echo json_encode(['success' => false, 'error' => $langs->trans("ErrorCantCreateDir")]);
        exit;
    }
}
// 2. Generate unique filename
$filename = 'sample_document_' . dol_print_date(dol_now(), 'dayhourlog') . '.pdf';
$filepath = DOL_DATA_ROOT . '/temp/' . $filename;

// 3. Save PDF to file
$pdf->Output($filepath, 'F');

// 4. Create ECM database entry
require_once DOL_DOCUMENT_ROOT . '/ecm/class/ecmfiles.class.php';
$ecmfile = new EcmFiles($db);
$ecmfile->filepath = $filepath;
$ecmfile->filename = $filename;
$ecmfile->label = $langs->trans("SampleDocument");
$ecmfile->entity = $conf->entity;
$ecmfile->share = 'shared';
$result = $ecmfile->create($user);
if ($result < 0) {
    echo json_encode(['success' => false, 'error' => $ecmfile->error]);
    exit;
}

// 5. Generate secure download URL
$download_url = DOL_URL_ROOT . '/document.php?modulepart=temp&file=' . urlencode($filename);
//$download_url .= urlencode('/documents/temp/' . $filename) . '&entity=' . $conf->entity;

// 6. Return JSON response
header('Content-Type: application/json; charset=utf-8');
echo json_encode([
    'success' => true,
    'file' => $download_url
]);
exit;
*/


require_once '../../../main.inc.php';
require_once DOL_DOCUMENT_ROOT . '/core/lib/files.lib.php';
require_once DOL_DOCUMENT_ROOT . '/core/lib/pdf.lib.php';
ob_end_clean();

// Load language files
$langs->load("main");
$langs->load("errors");

// Create PDF instance
$pdf = pdf_getInstance();
$pdf->SetFont(pdf_getPDFFont($langs), '', 12);
$pdf->Open();
$pdf->AddPage();

// Add sample content
$pdf->SetFont('', 'B', 16);
$pdf->Cell(0, 10, $langs->trans("SampleDocument"), 0, 1, 'C');
$pdf->SetFont('', '', 12);
$pdf->MultiCell(0, 10, $langs->trans("ThisIsASamplePDFDocumentGeneratedByDolibarr"), 0, 'L');

// 1. Save under DOL_DATA_ROOT/ecm/temp/
$subdir = 'temp';
$filename = 'sample_document_' . dol_print_date(dol_now(), 'dayhourlog') . '.pdf';
$relpath = $subdir . '/' . $filename;
$fullpath = DOL_DATA_ROOT . '/ecm/' . $relpath;

// Ensure directory exists
dol_mkdir(dirname($fullpath));

// 2. Output PDF to file
$pdf->Output($fullpath, 'F');

// 3. Create ECM database entry
require_once DOL_DOCUMENT_ROOT . '/ecm/class/ecmfiles.class.php';
$ecmfile = new EcmFiles($db);
$ecmfile->filepath = $subdir; // Only relative subdir
$ecmfile->filename = $filename;
$ecmfile->label = $langs->trans("SampleDocument");
$ecmfile->entity = $conf->entity;
$ecmfile->share = 'shared';
$result = $ecmfile->create($user);
if ($result < 0) {
    echo json_encode(['success' => false, 'error' => $ecmfile->error]);
    exit;
}

// 4. Return URL using document.php
$download_url = DOL_URL_ROOT . '/document.php?modulepart=ecm&file=' . urlencode($relpath);

// 5. Return JSON
header('Content-Type: application/json; charset=utf-8');
echo json_encode([
    'success' => true,
    'file' => $download_url
]);
exit;
