!/bin/bash

set -euo pipefail
SECRET=$(tpm2_nvread 0x1500016 -C 0x1500016 -P pcr:sha256:1=measured.pcrvalues)

%echo "The secret is: ${SECRET}"

AES_KEY=$(echo -n "$SECRET" | openssl dgst -sha256 -binary)


%echo "The AES_KEY is: ${AES_KEY}"

openssl enc -aes256 -pbkdf2 -in client-dev.key -out client-dev.key.enc -pass "pass:${AES_KEY}"

```latex
\subsubsection{Tworzenie i wykorzystanie polityki PCR w TPM 2.0}

Polityka może zostać utworzona za pomocą polecenia \texttt{tpm2\_createpolicy} z określeniem indeksów PCR, które mają być powiązane z polityką.

\begin{verbatim}
tpm2_pcrread -o measured.pcrvalues sha256:0,1,2
\end{verbatim}

Powyższe polecenie odczytuje wartości PCR (skrót) z indeksów 0, 1 i 2, a następnie zapisuje je w pliku \texttt{measured.pcrvalues}.

\begin{verbatim}
tpm2_createpolicy --policy-pcr -l sha256:0,1,2 -f measured.pcrvalues \
  -L measured.policy
\end{verbatim}

Parametr \texttt{measured.policy} stanowi plik wyjściowy zawierający politykę, a indeksy PCR (SHA256) 0, 1 i 2 są uwzględniane w procesie tworzenia polityki.

\paragraph{Definiowanie obszaru NVRAM}

Przestrzeń NVRAM może zostać utworzona przy użyciu polecenia \texttt{tpm2\_nvdefine}. Podczas tworzenia można przypisać politykę do indeksu NV.

\begin{verbatim}
tpm2_nvdefine 0x1500016 -C o -s 32 -L measured.policy \
  -a "policyread|policywrite"
\end{verbatim}

Parametry polecenia oznaczają:
\begin{itemize}
    \item \texttt{0x1500016} -- indeks NV,
    \item \texttt{measured.policy} -- plik polityki,
    \item \texttt{policyread|policywrite} -- atrybuty przestrzeni NV.
\end{itemize}

\paragraph{Odczyt i zapis do przestrzeni NVRAM}

Aby odczytać lub zapisać dane do przestrzeni NV, polityka musi zostać spełniona. Wartości PCR z momentu zapieczętowania danych muszą być spójne z wartościami podczas odczytu lub zapisu do przestrzeni NV.

\begin{verbatim}
echo -n "top secret!!" | tpm2_nvwrite 0x1500016 -C 0x1500016 \
  -P pcr:sha256:0,1,2=measured.pcrvalues -i -
\end{verbatim}

Parametry oznaczają:
\begin{itemize}
    \item \texttt{0x1500016} -- uchwyt NVRAM oraz lokalizacja przechowywania polityki,
    \item \texttt{pcr:sha256:0,1,2=measured.pcrvalues} -- weryfikacja zgodności wartości PCR z wcześniej wygenerowanymi wartościami przed zapisem danych do obszaru NVRAM.
\end{itemize}

Analogiczna weryfikacja jest przeprowadzana podczas odczytu z indeksu:

\begin{verbatim}
tpm2_nvread 0x1500016 -C 0x1500016 \
  -P pcr:sha256:0,1,2=measured.pcrvalues
\end{verbatim}

W ten sposób wrażliwe dane mogą zostać zapieczętowane i chronione przez politykę w TPM. Możliwe jest również zapieczętowanie klucza do zestawu wartości PCR i wykorzystanie go do szyfrowania danych. W momencie deszyfrowania konieczne jest najpierw spełnienie polityki, a następnie użycie klucza do odszyfrowania danych.
```
