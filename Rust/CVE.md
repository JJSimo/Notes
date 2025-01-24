### **CVE-2014-6271 (Shellshock)**
- **Livello**: Basso.
- **Descrizione**: Vulnerabilità in Bash che consente l'esecuzione di codice arbitrario tramite variabili d'ambiente.
- **Ambiente di test**:
    1. Installa una vecchia versione di Bash su una VM con Ubuntu
       `sudo apt-get install bash=4.3-7ubuntu1`
        
    2. Configura un server CGI vulnerabile:
        - Installa Apache:
          `sudo apt install apache2`
            
        - Abilita CGI e posiziona uno script vulnerabile in `/usr/lib/cgi-bin/`
          
- **Obiettivo**: Creare una richiesta HTTP che inietta comandi tramite la variabile d'ambiente.

---
### **2. CVE-2018-11776 (Apache Struts OGNL Injection)**
- **Livello**: Basso.
- **Descrizione**: Vulnerabilità di iniezione OGNL in Apache Struts che consente l'esecuzione di codice remoto.
- **Ambiente di test**:
    1. Scarica Apache Tomcat:
       `sudo apt install tomcat9`
        
    2. Scarica e installa una versione vulnerabile di Apache Struts.
    3. Carica una web app demo vulnerabile.
- **Obiettivo**: Invio di payload OGNL in richieste HTTP.

---
### **3. CVE-2017-5638 (Apache Struts RCE)**
- **Livello**: Medio.
- **Descrizione**: RCE causato dalla gestione impropria di richieste multipart in Apache Struts.
- **Ambiente di test**:
    1. Stessa configurazione di CVE-2018-11776.
    2. Carica una web app vulnerabile e abilita richieste multipart.
- **Obiettivo**: Creare una richiesta HTTP multipart malformata.

---
### **4. CVE-2014-0160 (Heartbleed)**
- **Livello**: Medio.
- **Descrizione**: Vulnerabilità in OpenSSL che consente la lettura di memoria arbitraria.
- **Ambiente di test**:
    1. Configura un server con una vecchia versione di OpenSSL (1.0.1f):
       `sudo apt install openssl=1.0.1f`
        
    2. Crea un semplice server HTTPS vulnerabile.
- **Obiettivo**: Creare una richiesta TLS malformata per leggere blocchi di memoria del server.

---
### **5. CVE-2021-44228 (Log4Shell)**
- **Livello**: Medio.
- **Descrizione**: Vulnerabilità in Log4j che consente RCE tramite JNDI.
- **Ambiente di test**:
    1. Configura un server Java con una versione vulnerabile di Log4j.
    2. Usa Docker per creare un server LDAP falso per ricevere payload:
       `docker run -p 1389:1389 -it ghcr.io/kozmer/log4j-shell-poc`
        
- **Obiettivo**: Invio di un payload JNDI per eseguire comandi remoti.

---
### **6. CVE-2022-0847 (Dirty Pipe)**
- **Livello**: Medio-Alto.
- **Descrizione**: Vulnerabilità Linux che consente di sovrascrivere file arbitrari tramite pipe.
- **Ambiente di test**:
    1. Usa una macchina con Linux Kernel 5.8-5.10.
    2. Configura un utente con accesso limitato per testare l'evasione.
- **Obiettivo**: Creare un exploit Rust per modificare file di root senza permessi.

---
### **7. CVE-2021-3156 (Sudo Overflow)**
- **Livello**: Alto.
- **Descrizione**: Overflow nel comando `sudo` che consente escalation di privilegi.
- **Ambiente di test**:
    1. Scarica una versione vulnerabile di `sudo` (1.8.32):
        `wget https://.../sudo-1.8.32.tar.gz`
        
    2. Compila e installa la versione vulnerabile.
- **Obiettivo**: Creare un payload che sfrutta l’overflow per ottenere privilegi di root.

---
### **8. CVE-2019-0708 (BlueKeep)**
- **Livello**: Alto.
- **Descrizione**: RCE su Windows tramite RDP.
- **Ambiente di test**:
    1. Usa una macchina virtuale con Windows Server 2008.
    2. Configura RDP e disabilita le patch.
- **Obiettivo**: Creare un exploit per inviare pacchetti RDP malformati.

---
### **9. CVE-2019-5736 (Docker Escape)**
- **Livello**: Alto.
- **Descrizione**: Escape di container Docker sfruttando una vulnerabilità in `runc`.
- **Ambiente di test**:
    1. Configura Docker con una versione vulnerabile di `runc`.
    2. Avvia un container e prova a evadere l’ambiente.
- **Obiettivo**: Creare un exploit Rust per manipolare i processi del container.

---
### **10. CVE-2017-0144 (EternalBlue)**
- **Livello**: Molto Alto.
- **Descrizione**: RCE su Windows tramite SMBv1.
- **Ambiente di test**:
    1. Configura una VM con Windows XP o Windows 7 non patchato.
    2. Abilita SMBv1.
- **Obiettivo**: Scrivere un exploit che invia pacchetti SMB malformati per eseguire codice.