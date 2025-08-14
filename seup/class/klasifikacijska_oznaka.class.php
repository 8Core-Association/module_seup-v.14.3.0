<?php

class Klasifikacijska_oznaka
{
    private $klasa_br;
    private $sadrzaj;
    private $dosje_broj;
    private $vrijeme_cuvanja;
    private $opis_klasifikacijske_oznake;
    private $ID;
    // function __construct()
    // {
    //     $this->klasa_br = '';
    //     $this->sadrzaj = '';
    //     $this->dosje_broj = '';
    //     $this->vrijeme_cuvanja= '0';
    //     $this->opis_klasifikacijske_oznake = '';

    // }
    // Getters
    public function getKlasa_br()
    {
        return $this->klasa_br;
    }

    public function getSadrzaj()
    {
        return $this->sadrzaj;
    }

    public function getDosjeBroj()
    {
        return $this->dosje_broj;
    }

    public function getVrijemeCuvanja()
    {
        return $this->vrijeme_cuvanja;
    }

    public function getOpisKlasifikacijskeOznake()
    {
        return $this->opis_klasifikacijske_oznake;
    }

    public function getIDKlasifikacijskeOznake()
    {
        return $this->ID;
    }
    // Setters
    public function setKlasa_br($value)
    {
        $this->klasa_br = $value;
    }

    public function setSadrzaj($value)
    {
        $this->sadrzaj = $value;
    }

    public function setDosjeBroj($value)
    {
        $this->dosje_broj = $value;
    }

    public function setVrijemeCuvanja($value)
    { 
        $this->vrijeme_cuvanja = $value;
    }

    public function setOpisKlasifikacijskeOznake($value)
    {
        $this->opis_klasifikacijske_oznake = $value;
    }

    public function setIDKlasifikacijskeOznake($value)
    {
        $this->ID = $value;
    }
    // Metoda za cast mjesavine int i string podatka u cisti integer radi jednostavnijeg baratanja s bazom
    public function CastVrijemeCuvanjaToInt($vrijeme_cuvanja_raw)
    {
        return ($vrijeme_cuvanja_raw === 'permanent') ? 0 : (int)$vrijeme_cuvanja_raw;
    }
}
