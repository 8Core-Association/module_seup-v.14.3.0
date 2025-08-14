<?php

class Predmet
{
    private $Klasa_br;
    private $Sadrzaj;
    private $dosje_br;
    private $Vrijeme_cuvanja;
    private $ID;
    private $ID_interna_oznaka_korisnika;
    private $god;
    private $rbr_predmeta;
    private $naziv;

    public function getID()
    {
        return $this->ID;
    }

    public function setID($ID)
    {
        $this->ID = $ID;
    }

    public function getIDInternaOznakaKorisnika()
    {
        return $this->ID_interna_oznaka_korisnika;
    }
    public function setIDInternaOznakaKorisnika($ID_interna_oznaka_korisnika)
    {
        $this->ID_interna_oznaka_korisnika = $ID_interna_oznaka_korisnika;
    }
    public function getGod()
    {
        return $this->god;
    }
    public function setGod($god)
    {
        $this->god = $god;
    }
    public function getRbrPredmeta()
    {
        return $this->rbr_predmeta;
    }
    public function setRbrPredmeta($rbr_predmeta)
    {
        $this->rbr_predmeta = $rbr_predmeta;
    }
    public function getNaziv()
    {
        return $this->naziv;
    }
    public function setNaziv($naziv)
    {
        $this->naziv = $naziv;
    }

    public function getKlasaBr()
    {
        return $this->Klasa_br;
    }

    public function setKlasaBr($Klasa_br)
    {
        $this->Klasa_br = $Klasa_br;
    }

       public function getSadrzaj()
    {
        return $this->Sadrzaj;
    }

    public function setSadrzaj($Sadrzaj)
    {
        $this->Sadrzaj = $Sadrzaj;
    }

    public function getDosjeBroj()
    {
        return $this->dosje_br;
    }

    public function setDosjeBroj($dosje_br)
    {
        $this->dosje_br = $dosje_br;
    }
  
    public function getVrijemeCuvanja()
    {
        return $this->Vrijeme_cuvanja;
    }

    public function setVrijemeCuvanja($Vrijeme_cuvanja)
    {
        $this->Vrijeme_cuvanja = $Vrijeme_cuvanja;
    }
}

?>