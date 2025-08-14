<?php

class Interna_oznaka_korisnika
{
    private $ime_prezime;
    private $rbr_korisnika;
    private $radno_mjesto_korisnika;
    private $ID;

    public function __construct($ime_prezime = null, $rbr_korisnika = null, $radno_mjesto_korisnika = null)
    {
        $this->ime_prezime = $ime_prezime;
        $this->rbr_korisnika = $rbr_korisnika;
        $this->radno_mjesto_korisnika = $radno_mjesto_korisnika;
    }

    public function getIme_prezime()
    {
        return $this->ime_prezime;
    }
    public function getRbr_korisnika()
    {
        return $this->rbr_korisnika;
    }
    public function getRadno_mjesto_korisnika()
    {
        return $this->radno_mjesto_korisnika;
    }
    public function getID()
    {
        return $this->ID;
    }

    public function setIme_prezime($value)
    {
        $this->ime_prezime = $value;
    }

    public function setRbr_korisnika($value)
    {
        $this->rbr_korisnika = $value;
    }

    public function setRadno_mjesto_korisnika($value)
    {
        $this->radno_mjesto_korisnika = $value;
    }
    
    public function setID($value)
    {
        $this->ID = $value;
    }
}
