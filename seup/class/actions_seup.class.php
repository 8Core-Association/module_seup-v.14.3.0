function addMoreActionsButtons($parameters, &$object, &$action) {
    global $conf;
    
    // OnlyOffice integracija
    if ($object->type == 'document') {
        $url = $conf->global->ONLYOFFICE_SERVER_URL.'/editors/editor';
        $doc_url = dol_buildpath('/document.php',1).'?modulepart=seup&file='.urlencode($object->ref);
        
        print '<a class="butAction" href="'.$url.'?file='.$doc_url.'">Otvori u OnlyOffice</a>';
    }
}