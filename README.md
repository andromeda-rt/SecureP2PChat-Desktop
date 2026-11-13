# Arhitectura Criptografică și Diagramarea Aplicației Desktop Python (SecureP2PChat)

Acest document reprezintă specificația tehnică oficială a aplicației **SecureP2PChat Desktop (Windows/Linux/macOS)** în Python. Conține toate diagramele **Mermaid** pentru modulele interne, bucla asincronă, stocarea în seiful criptat (Vault), transferurile media, interacțiunea cu releul și interoperabilitatea cu Android.

---

## 1. Arhitectura Modulilor Aplicației Desktop Python

 Diagrama de structură a modulelor din clientul Python și interacțiunea dintre interfața grafică (`CustomTkinter`), rețeaua asincronă (`asyncio`), motorul criptografic și baza de date criptată.

```mermaid
flowchart TD
    subgraph UIThread ["Fir Execuție Interfață Grafică (CustomTkinter)"]
        GUI["gui.py (CustomTkinter UI)<br/>Dark Electro-Blue Theme"]
        VoiceRecorderMod["audio_recorder.py<br/>Înregistrare Voce WAV"]
    end

    subgraph AsyncLoop ["Buclă Asincronă (asyncio Loop)"]
        MainApp["main.py (App Controller)<br/>Orchestrator Evenimente & Rețea"]
        SignalingMod["signaling.py (SignalingClient)<br/>Comenzi JSON Lines + Ed25519"]
        ProxyPoolMod["proxy_pool.py & network.py<br/>SOCKS5 Tor Proxy & Direct P2P"]
    end

    subgraph CryptoLayer ["Stratul Criptografic & Ratchet"]
        CryptoEngineMod["crypto_engine.py<br/>Argon2id, X25519, Ed25519, ChaCha20-Poly1305"]
        FSChainMod["fs_chain.py<br/>FS2 Symmetric Ratchet 1:1"]
        GSKMod["group_sender_key.py<br/>GSK1 Sender Chains"]
        TreeKEMMod["treekem_group.py<br/>TreeKEM O(log N) MLS Group Tree"]
    end

    subgraph StorageLayer ["Stratul de Stocare Criptată"]
        StorageMod["storage.py (SQLite DB)<br/>Criptată cu Argon2id Master Key"]
        VaultMod["file_vault.py (Encrypted Vault)<br/>Criptează poze / audio / fișiere"]
    end

    GUI <-->|asyncio.run_coroutine_threadsafe| MainApp
    VoiceRecorderMod --> GUI
    MainApp <--> SignalingMod
    SignalingMod <--> ProxyPoolMod
    MainApp <--> CryptoLayer
    CryptoLayer <--> StorageLayer
    MainApp <--> VaultMod
```

---

## 2. Arborele Ierarhic al Cheilor și Stocarea Locală (Storage & Vault)

 Cum derivă aplicația desktop cheia Master din parola utilizatorului pentru a proteja baza de date locală SQLite și fișierele din seiful criptat (`.vault`):

```mermaid
flowchart TD
    UserPassword["Parolă Utilizator Desktop + Salt (16B)"] --> Argon2idEngine["Argon2id (t=3, m=64MB, p=4)"]
    Argon2idEngine --> MasterKey["Master Key (32 bytes - Protejată în RAM)"]

    MasterKey --> EncryptDB["Criptează Baza de Date SQLite (storage.py)"]
    MasterKey --> EncryptVault["Criptează Fișierele Media (.vault) (file_vault.py)"]

    MasterKey --> IdentityX25519["Identity X25519 Keypair (Acord Cheie)"]
    MasterKey --> IdentityEd25519["Identity Ed25519 Keypair (Semnături Releu)"]

    IdentityX25519 --> SessionKey["Session Key (32B) (FS2 1:1 Ratchet)"]
    SessionKey --> FS2Chain["FS2 Send / Receive Chain Keys"]
    FS2Chain --> SingleUseKeys["Message Keys Single-Use (fill(0))"]

    EncryptVault --> TempExport["Export Temporar în temp/ la Vizualizare/Redare Audio"]
```

---

## 3. Bucla Asincronă de Rețea și Sondarea Releului (Relay Poll Loop)

 Sincronizarea asincronă între interfața grafică și serverul de semnalizare prin polling anonim Tor v3:

```mermaid
sequenceDiagram
    autonumber
    participant GUI as Interfață CustomTkinter (gui.py)
    participant App as App Controller (main.py)
    participant Signal as Client Semnalizare (signaling.py)
    participant Relay as Server Releu (.onion / TLS 1.3)
    participant Inbox as Pending Relay Inbox

    App->>Signal: Pornire Buclă Poll (relay_poll) la fiecare 1.5s
    loop La fiecare 1.5 secunde (Poll Interval)
        Signal->>Relay: Comandă relay_poll semnată Ed25519
        Relay-->>Signal: Returnează mesaje noi din căsuța ephemeră
        alt Există mesaje primite
            Signal->>App: Transmite pachetele brute
            alt Cheia 1:1 cu expeditorul nu există încă
                App->>Inbox: Salvează pachetul în _pending_relay_inbox
                App->>Signal: Trimite MSG_HELLO către expeditor
            else Cheia 1:1 există
                App->>App: Decriptează FS2 / GSK1 ChaCha20-Poly1305
                App->>GUI: Actualizează chat-ul (Bule Text / Foto / Audio)
                App->>Signal: Trimite confirmare relay_ack(msg_ids)
            end
        end
    end
```

---

## 4. Transferul și Redarea Mesajelor Vocale și Imagini în Interfață

 Fluxul complet de la înregistrarea audio / selectarea imaginii pe desktop, fragmentarea în bucăți de 64 KiB, până la recepție, decriptare și redare:

```mermaid
sequenceDiagram
    autonumber
    participant User as Utilizator Desktop
    participant GUI as CustomTkinter GUI
    participant Recorder as VoiceRecorder (audio_recorder.py)
    participant App as App Main Controller
    participant Relay as Server Releu
    participant Dest as Destinatar (Android / Desktop)

    User->>GUI: Apasă butonul de Înregistrare Vocală (🎤)
    GUI->>Recorder: Pornire înregistrare audio WAV
    User->>GUI: Apasă Stop (■)
    GUI->>Recorder: Oprire înregistrare -> Fișier audio WAV
    Recorder->>App: Returnează cale fișier audio temporar
    App->>App: Sparge fișierul audio în bucăți de 64 KiB
    App->>Relay: Trimitere FILE_START (nume, dimensiune, total_chunks)
    Relay-->>Dest: Livrare FILE_START
    loop Pentru fiecare bucată i de la 0 la total_chunks - 1
        App->>Relay: Trimitere FILE_CHUNK (index = i, date Base64)
        Relay-->>Dest: Livrare FILE_CHUNK
    end
    App->>Relay: Trimitere FILE_END
    Relay-->>Dest: Livrare FILE_END
    Note over Dest: Destinatarul reasamblează fișierul, îl salvează în Vault
    Note over Dest: Afișează bula audio 🎵 cu butonul "Redă audio"
```

---

## 5. Criptografia în Grupuri Desktop (GSK1 & Epoch Key Distribution)

 Cum funcționează sincronizarea cheilor de grup pe desktop la alăturarea sau trimiterea mesajelor de către utilizatorii Windows/Android:

```mermaid
flowchart TD
    subgraph GroupCreation ["Creare & Rotație Epocă Grup"]
        Creator["Creator Grup Desktop"] -->|Generează aleator 32B| NewEpochSecret["New Epoch Secret (Epoca E)"]
        NewEpochSecret -->|Criptat FS2 individual| MemberList["Fiecare Membru Autorizat (Android / Windows)"]
    end

    subgraph GSKDerivation ["Derivare Lanțuri Expeditor (GSK1)"]
        MemberList -->|Aplicație Desktop/Android| LoadSecret["Salvare în DB: gk|group_id|epoch"]
        LoadSecret --> DeriveGSK["Derivare Lanț GSK1 Expeditor<br/>HKDF(epoch_secret, group_id, E, sender_id)"]
        DeriveGSK --> MsgKeys["Generare Cheie Mesaj Single-Use (fill(0))"]
        MsgKeys --> EncryptPayload["Criptare SPC2-AEAD ChaCha20-Poly1305"]
    end
```

---

## 6. Interoperabilitatea Completă Android ── Windows Python

 Trecerea datelor între cele două stive tehnologice prin protocolul binar/JSON unificat:

```mermaid
flowchart LR
    subgraph StivaAndroid ["Client Android (Kotlin)"]
        AndroidCore["ChatManager.kt / Protocol.kt"]
        AndroidCrypto["ForwardSecrecyChain.kt / GroupSenderKeyChain.kt"]
    end

    subgraph ProtocolUnificat ["Protocol Binar & JSON Lines"]
        FS2Header["Header FS2: 'FS2' (3B) + SessionID (16B) + Counter (4B)"]
        GSK1Header["Header GSK1: 'GSK1' + Epoch (8B) + Counter (4B)"]
        FileChunks["Bucăți Fișiere: 64 KiB per Chunk"]
    end

    subgraph StivaWindows ["Client Windows (Python)"]
        PyMain["client/main.py / shared/protocol.py"]
        PyCrypto["client/fs_chain.py / client/group_sender_key.py"]
    end

    StivaAndroid <-->|Pachete Binar/JSON Criptate| ProtocolUnificat
    ProtocolUnificat <-->|Pachete Binar/JSON Criptate| StivaWindows
```

---

## 7. Specificația Modulilor Sursă Desktop

| Fișier Sursă Python | Linii Cod | Funcție Principală și Detalii Criptografice |
| :--- | :--- | :--- |
| `client/main.py` | ~2970 | **Controller Principal**: Buclă asincronă, gestiune stare chat, `_pending_relay_inbox`, flushes. |
| `client/gui.py` | ~1030 | **Interfață CustomTkinter**: Bule chat, previzualizare poze, player audio, picker fișiere. |
| `client/crypto_engine.py` | ~150 | **Criptografie Bază**: Argon2id, X25519, Ed25519, ChaCha20-Poly1305 (plic `SPC2`), HSalsa20. |
| `client/fs_chain.py` | ~150 | **Ratchet 1:1 (FS2)**: Lanț simetric per direcție, HKDF-SHA256, fereastră skip max 1024. |
| `client/group_sender_key.py`| ~120 | **Ratchet Grup (GSK1)**: Derivare lanț expeditor din `epoch_secret` și zeroizare RAM (`fill(0)`). |
| `client/treekem_group.py` | ~350 | **MLS Group Tree**: Arbore logaritmic TreeKEM $O(\log N)$ pentru re-cheierea grupurilor mari. |
| `client/storage.py` | ~670 | **Stocare SQLite Criptată**: Protecție cu Argon2id Master Key a contactelor și stărilor ratchet. |
| `client/file_vault.py` | ~50 | **Seif Fișiere**: Salvarea criptată `.vault` a pozelor, audio-ului și atașamentelor pe disc. |
| `client/audio_recorder.py` | ~60 | **Înregistrare Voce**: Înregistrare audio din microfon în fișiere temporare WAV. |
| `signaling_server.py` | ~840 | **Server Releu**: Server hibrid anonim, verificări Ed25519, cozi de mesaje ephemere în RAM. |
