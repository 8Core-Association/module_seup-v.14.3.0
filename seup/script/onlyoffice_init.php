<?php
require '../../main.inc.php';

header('Content-Type: application/json');

$config = array(
    "document" => array(
        "fileType" => $_GET['fileType'],
        "key" => uniqid(),
        "title" => $_GET['title'],
        "url" => $_GET['url'],
        "permissions" => array(
            "edit" => ($user->rights->seup->write ? true : false)
        )
    ),
    "editorConfig" => array(
        "callbackUrl" => dol_buildpath('/seup/script/onlyoffice_callback.php',1)
    )
);

print json_encode($config);