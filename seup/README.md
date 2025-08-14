# SEUP - Sustav Elektronskog Uredskog Poslovanja

**Moderni modul za upravljanje dokumentima i predmetima u javnoj upravi**

## 🚀 Značajke

- **📁 Upravljanje predmetima** - Kreiranje i praćenje predmeta s klasifikacijskim oznakama
- **📄 Upravljanje dokumentima** - Upload, pregled i organizacija dokumenata
- **🏢 Oznake ustanova** - Konfiguracija osnovnih podataka ustanove
- **👥 Interne oznake korisnika** - Upravljanje korisničkim oznakama i radnim mjestima
- **🗂️ Plan klasifikacijskih oznaka** - Hijerarhijski sustav klasifikacije
- **🏷️ Tagovi** - Fleksibilno označavanje s color pickerom
- **📊 Statistike** - Pregled aktivnosti i izvještaji
- **🎨 Moderni UI** - Responzivni dizajn s naprednim animacijama

## 📋 Funkcionalnosti

### Predmeti
- Kreiranje novih predmeta s automatskim generiranjem rednih brojeva
- Povezivanje s klasifikacijskim oznakama i zaposlenicima
- Upravljanje prilozima i dokumentima
- Praćenje datuma otvaranja i statusa

### Dokumenti
- Upload dokumenata (DOCX, XLSX, PDF, slike)
- Automatska organizacija u direktorije po predmetima
- Pregled i download dokumenata
- Integracija s ECM sustavom

### Administracija
- Postavke oznaka ustanova (format: 0000-0-0)
- Upravljanje korisničkim oznakama (0-99)
- Plan klasifikacijskih oznaka s vremenom čuvanja
- Tagovi s color pickerom za kategorizaciju

## 🎨 Dizajn

- **Apple-level estetika** - Čist, sofisticiran dizajn
- **Responzivni layout** - Optimizirano za sve uređaje
- **Animacije i micro-interakcije** - Smooth UX
- **Accessibility** - Keyboard navigation i screen reader podrška
- **Dark/Light mode** - Automatska detekcija preferencija

## 🛠️ Tehnologije

- **Backend**: PHP 7.1+, MySQL/MariaDB
- **Frontend**: HTML5, CSS3, JavaScript ES6+
- **Framework**: Dolibarr ERP & CRM
- **UI**: Font Awesome 6, Inter font, CSS Grid/Flexbox
- **Security**: CSRF protection, SQL injection prevention

Other external modules are available on [Dolistore.com](https://www.dolistore.com).

## Translations

Translations can be completed manually by editing files in the module directories under `langs`.

<!--
This module contains also a sample configuration for Transifex, under the hidden directory [.tx](.tx), so it is possible to manage translation using this service.

For more information, see the [translator's documentation](https://wiki.dolibarr.org/index.php/Translator_documentation).

There is a [Transifex project](https://transifex.com/projects/p/dolibarr-module-template) for this module.
-->


## Installation

Prerequisites: You must have Dolibarr ERP & CRM software installed. You can download it from [Dolistore.org](https://www.dolibarr.org).
You can also get a ready-to-use instance in the cloud from https://saas.dolibarr.org


### From the ZIP file and GUI interface

If the module is a ready-to-deploy zip file, so with a name `module_xxx-version.zip` (e.g., when downloading it from a marketplace like [Dolistore](https://www.dolistore.com)),
go to menu `Home> Setup> Modules> Deploy external module` and upload the zip file.

<!--

Note: If this screen tells you that there is no "custom" directory, check that your setup is correct:

- In your Dolibarr installation directory, edit the `htdocs/conf/conf.php` file and check that following lines are not commented:

    ```php
    //$dolibarr_main_url_root_alt ...
    //$dolibarr_main_document_root_alt ...
    ```

- Uncomment them if necessary (delete the leading `//`) and assign the proper value according to your Dolibarr installation

    For example :

    - UNIX:
        ```php
        $dolibarr_main_url_root_alt = '/custom';
        $dolibarr_main_document_root_alt = '/var/www/Dolibarr/htdocs/custom';
        ```

    - Windows:
        ```php
        $dolibarr_main_url_root_alt = '/custom';
        $dolibarr_main_document_root_alt = 'C:/My Web Sites/Dolibarr/htdocs/custom';
        ```
-->

<!--

### From a GIT repository

Clone the repository in `$dolibarr_main_document_root_alt/seup`

```shell
cd ....../custom
git clone git@github.com:gitlogin/seup.git seup
```

-->

### Final steps

Using your browser:

  - Log into Dolibarr as a super-administrator
  - Go to "Setup"> "Modules"
  - You should now be able to find and enable the module



## Licenses

### Main code

GPLv3 or (at your option) any later version. See file COPYING for more information.

### Documentation

All texts and readme's are licensed under [GFDL](https://www.gnu.org/licenses/fdl-1.3.en.html).
