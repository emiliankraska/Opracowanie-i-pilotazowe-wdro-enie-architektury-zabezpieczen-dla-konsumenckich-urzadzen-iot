# Opracowanie-i-pilotazowe-wdro-enie-architektury-zabezpieczen-dla-konsumenckich-urzadzen-iot



Repozytorium zawiera kod oraz konfiguracje wykorzystane w pracy dyplomowej dotyczącej projektowania i pilotażowego wdrożenia architektury zabezpieczeń dla konsumenckich urządzeń IoT.  
Projekt opiera się na systemie **Embedded Linux** budowanym przy użyciu **Buildroot**, integracji z **TPM**, oraz komunikacji **CoAP (libcoap)** zabezpieczonej TLS/mTLS.

Repozytorium **nie jest projektem produkcyjnym** – zawiera kod i dane przeznaczone do środowiska testowego.

---

## Struktura repozytorium
## DT/ – Device Tree Overlay

Katalog zawiera pliki **Device Tree Overlay** wykorzystywane do konfiguracji sprzętu na etapie bootowania systemu.

- `letstrust-tpm-overlay.dts`  
  Overlay Device Tree dla systemu Linux, umożliwiający obsługę modułu **TPM**.

- `uboot-tpm-slb9670-overlay.dts`  
  Overlay Device Tree dla **U-Boot**, konfiguruje obsługę sprzętowego TPM SLB9670 na etapie bootloadera.

---

## konfiguracja.config – konfiguracja Buildroot

Główny plik konfiguracyjny systemu tworzonego przy użyciu **Buildroot**.  
Określa m.in.:

- architekturę systemu,
- używane pakiety i biblioteki,
- konfigurację systemu plików,
- narzędzia kryptograficzne,
- wsparcie dla TPM oraz libcoap.

Plik należy zaimportować do Buildroot (np. `make defconfig` lub przez `make menuconfig`).

---

## libcoap/ – implementacja komunikacji CoAP

Katalog zawiera kod źródłowy klientów i serwera **CoAP** opartych o bibliotekę **libcoap**, wraz z certyfikatami i plikami pomocniczymi.

### libcoap/CA/ – lokalne centrum certyfikacji

Pliki związane z testowym **Certificate Authority (CA)**:

- `ca.crt`, `ca.key` – certyfikat i klucz CA,
- `certs/` – certyfikaty klientów,
- `client-dev.crt`, `client-dev.key` – certyfikat i klucz klienta developerskiego.

---

### libcoap/client_dir/ – klient CoAP (wersja standardowa)

Zawiera kod oraz certyfikaty dla podstawowego klienta CoAP odpalanego na zwykłym PC:

- `client.cc`, `client_alt.cc` – implementacje klienta,
- `common.cc`, `common.hh` – wspólna logika wykorzystywana przez klienta,
- `certs/` – certyfikaty klienta,
- `Makefile` – budowanie binarki klienta.

---

### libcoap/dev_client_dir/ – klient developerski

Wersja klienta na urządzenie, używana do testów i eksperymentów:

- `client-dev.cc`, `client-dev-alt2.cc` – alternatywne implementacje klienta,
- `encrypt.sh` – skrypt pomocniczy (np. szyfrowanie / sealing),
- `run-client.sh` – uruchamianie klienta,
- `admin_id_ed25519` – klucz SSH,
- `makefile` – budowanie wersji developerskiej.

---

### libcoap/server_dir/ – serwer CoAP

Implementacja serwera CoAP:

- `server.cc`, `server-alt.cc` – kod serwera,
- `common.cc`, `common.hh` – wspólne komponenty,
- `certs/` – certyfikaty serwera,
- `mydb.db` – lokalna baza danych wykorzystywana przez serwer,
- `secret2.bin` – dane binarne używane w testach,
- `Makefile` – budowanie binarki serwera.

---

## rootfs-overlay/ – overlay systemu plików rootfs

Katalog zawiera pliki, które są **bezpośrednio kopiowane do systemu docelowego** podczas budowania obrazu przez Buildroot.

### rootfs-overlay/client/

Pliki związane z klientem w systemie docelowym:

- `bin/client-dev` – binarka klienta,
- `certs/` – certyfikaty, klucze oraz skrypty:
  - `encrypt.sh`
  - `seal.sh`
  - `secret.bin`
- `run-client.sh` – skrypt uruchamiający klienta.

---

### rootfs-overlay/etc/

Pliki konfiguracyjne systemu:

- `dropbear/authorized_keys` – klucze SSH dla logowania,
- `init.d/S99setupscript` – skrypt inicjalizacyjny uruchamiany przy starcie systemu.

---

## Uwagi końcowe

- Repozytorium służy do celów badawczych i demonstracyjnych.
- Certyfikaty oraz klucze są elementem środowiska testowego.
- Struktura projektu jest dostosowana do systemów embedded opartych o Buildroot
