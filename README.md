# 🔍 Checklist de Pentest

---

## Sumário

* [Visão Geral](#visão-geral)
* [Como usar este repositório](#como-usar-este-repositório)
* [Fase 1 — Enumeração](#fase-1---enumeração)

  * Varredura de rede
  * Reconhecimento web
  * Enumeração de serviços
* [Fase 2 — Acesso Inicial](#fase-2---acesso-inicial)

  * Exploração fácil
  * Ataques de credenciais
  * Vetores web
* [Fase 3 — Escalação de Privilégios](#fase-3---escalação-de-privilégios)

  * Recon local
  * Arquivos sensíveis
  * Ferramentas automatizadas
* [Comandos Úteis (Resumo)](#comandos-úteis-resumo)
* [Recursos e referências](#recursos-e-referências)
* [Modo Desafio (opcional)](#modo-desafio-opcional)
* [Responsabilidade & Ética](#responsabilidade--ética)

---

## Visão Geral

Este README apresenta um fluxo prático para avaliações de segurança (pentests) dividido em três fases: **Enumeração**, **Acesso Inicial** e **Escalação de Privilégios**. Contém checklists, exemplos de comandos e links para referências amplamente usadas pela comunidade. Use sempre em ambientes com autorização explícita.

---

## Como usar este repositório

1. Faça *fork* / clone deste repositório para o seu ambiente de trabalho.
2. Siga os checklists por fase — marque itens como concluídos durante os testes.
3. Documente achados em arquivos separados (`/reports`, `/notes`) com evidências e recomendações.
4. Atualize as seções de comandos e referências conforme suas ferramentas e metodologias.

---

# Fase 1 — Enumeração

## Varredura de Rede

* [ ] Varredura inicial (scripts + versão):

```bash
nmap -sC -sV -T4 -Pn <IP> -oN scans/initial.nmap
```

* [ ] Varredura completa de portas TCP:

```bash
nmap -p- <IP> -T4 -oN scans/ports.nmap
```

* [ ] Varredura UDP (top ports):

```bash
nmap -sU --top-ports 200 -T4 <IP> -oN scans/udp.nmap
```

## Análise de Serviços Abertos

* [ ] Identificar serviços e capturar banners
* [ ] Registrar versões e mapear possíveis exploits (`searchsploit`)
* [ ] Confirmar serviços manualmente com `nc`, `curl`, `openssl`

## Reconhecimento Web

* [ ] Identificar tecnologias: `whatweb`, `httpx`, Wappalyzer
* [ ] Enumerar subdomínios: `ffuf`, `gobuster`, `subfinder`
* [ ] Descobrir endpoints/paths: `ffuf`, `feroxbuster`, `dirsearch`
* [ ] Testar parâmetros e mapear pontos de injeção (Burp Suite, ParamSpider)
* [ ] Verificar CMS e plugins (ex.: `wpscan` para WordPress)

---

# Fase 2 — Acesso Inicial

## Vetores fáceis

* [ ] FTP anônimo
* [ ] SMB compartilhamentos abertos
* [ ] Credenciais padrão ou vazadas

## Exploração de vulnerabilidades conhecidas

* [ ] Buscar no `searchsploit` / Exploit-DB
* [ ] Testar PoCs com `curl`, `python` ou no Metasploit (`msfconsole`)

## Ataques de credenciais

* [ ] Password-spray (evitar bloqueio de contas): `crackmapexec` com cuidado
* [ ] Brute-force (quando autorizado): `hydra`, `ncrack`, `medusa`
* [ ] Verificar reuso de senha entre serviços

## Ataques Web comuns

* Injeção de comandos
* Upload inseguro de arquivos (ver paths e validações)
* SQLi (`sqlmap`) — usar com parâmetros controlados
* LFI / RFI — checar inclusão de arquivos e arquivos de log
* XSS, SSTI, CSRF — mapear pontos de entrada e impacto

---

# Fase 3 — Escalação de Privilégios

## Recon e contexto local

* Executar comandos básicos para coleta de contexto:

```bash
# Linux
echo "== user =="; whoami; id; uname -a
sudo -l

# Windows
whoami /all
systeminfo
```

* [ ] Procurar chaves SSH (`~/.ssh/id_rsa`) e arquivos `.env` com segredos
* [ ] Verificar binários SUID/SGID e permissões críticas
* [ ] Procurar históricos (`.bash_history`, `.mysql_history`) e backups
* [ ] Observar processos e cron jobs (`ps`, `crontab -l`, `pspy`)

## Ferramentas automatizadas

* LinPEAS / WinPEAS (PEASS-ng)
* `pspy` para detectar jobs e processos em background
* `windows-exploit-suggester` / `searchsploit` para exploits locais

## Técnicas úteis

* Se `sudo NOPASSWD` encontrado → consultar GTFOBins para possíveis vetores
* Se `SeImpersonatePrivilege` no Windows → investigar PrintSpoofer / JuicyPotato / RoguePotato

---

# Comandos Úteis (Resumo rápido)

```text
nmap -sC -sV -T4 -Pn <target>
wffuf -u http://<target>/FUZZ -w wordlist
searchsploit --nmap scans/initial.nmap
sqlmap -u "http://<target>/item.php?id=1" --batch
./linpeas.sh -a
winpeas.exe > winpeas.txt
crackmapexec smb <target> -u users.txt -p 'Password123'
```

---

# Recursos e Referências

* PayloadsAllTheThings — [https://github.com/swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
* HackTricks — [https://book.hacktricks.xyz](https://book.hacktricks.xyz)
* Exploit-DB — [https://www.exploit-db.com/](https://www.exploit-db.com/)
* GTFOBins — [https://gtfobins.github.io](https://gtfobins.github.io)
* LOLBAS — [https://lolbas-project.github.io](https://lolbas-project.github.io)
* PEASS-ng (LinPEAS / WinPEAS) — [https://github.com/peass-ng/PEASS-ng](https://github.com/peass-ng/PEASS-ng)
* SecLists — [https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)
* Revshells — [https://www.revshells.com/](https://www.revshells.com/)

---

