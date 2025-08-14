<?php

class Oznaka_ustanove
{
    private $ID_oznaka_ustanove;
    private $oznaka_ustanove;
    private $naziv_ustanove;

    public function getID_oznaka_ustanove()
    {
        return $this->ID_oznaka_ustanove;
    }
    public function getOznaka_ustanove()
    {
        return $this->oznaka_ustanove;
    }
    public function getNaziv_ustanove()
    {
        return $this->naziv_ustanove;
    }

    public function setID_oznaka_ustanove($value)
    {
        $this->ID_oznaka_ustanove = $value;
    }

    public function setOznaka_ustanove($value)
    {
        $this->oznaka_ustanove = $value;
    }

    public function setNaziv_ustanove($value)
    {
        $this->naziv_ustanove = $value;
    }
}
