# Segurança em Redes — TCP com RSA + Diffie-Hellman + Cifra de César

Trabalho prático da disciplina de Segurança da Informação.  
Implementação de comunicação TCP segura entre dois interlocutores (**Alice** e **Bob**) utilizando criptografia RSA autoral de 4096 bits para a troca de chaves via Diffie-Hellman e Cifra de César para cifrar as mensagens.

---

## Integrantes

- Adriana Monteiro  
- Analuz Marin  
- Matheus Xavier  
- Yasmin Maciel  

---

## Arquitetura

```
Alice (Client)                          Bob (Server)
──────────────────────────────────────────────────────
Gera par RSA (4096 bits)                Gera par RSA (4096 bits)
                 ←── pub_bob ───────────────────────
─── pub_alice ──────────────────────────────────────→
Gera R1
─── R1_enc (cifrado com pub_bob) ───────────────────→
                                        Decifra R1 com priv_bob
                                        Gera R2
                 ←── R2_enc (cifrado com pub_alice) ─
Decifra R2 com priv_alice

shift = (R1 XOR R2) % 26   ←── chave compartilhada ───→   shift = (R1 XOR R2) % 26

─── msg cifrada com César (shift) ──────────────────→
                                        Decifra → processa → cifra resposta
                 ←── resposta cifrada com César ─────
Decifra resposta
```

---

## Tecnologias utilizadas

- Python 3 (sem bibliotecas externas)
- Sockets TCP
- RSA autoral com chaves de 4096 bits
- Teste de primalidade Miller-Rabin (baseado no PrimoHyper — Fábio Cabrini, 2025)
- Diffie-Hellman com R1 e R2 trocados via RSA
- Cifra de César para cifragem das mensagens
- Wireshark para análise do tráfego

---

## Como executar

**Pré-requisito:** Python 3 instalado em ambas as máquinas.

### 1. No PC do Bob (servidor) — IP `10.1.70.6`

```bash
python server.py
```

O servidor vai gerar as chaves RSA e ficar aguardando conexão na porta `1300`.

### 2. No PC da Alice (cliente)

```bash
python client.py
```

A Alice vai gerar suas chaves RSA, conectar ao servidor e solicitar uma mensagem para enviar.

---

## Fluxo detalhado

| Etapa | O que acontece |
|---|---|
| 1 | Alice e Bob geram seus pares de chaves RSA de 4096 bits |
| 2 | Trocam chaves públicas via TCP (visível no Wireshark) |
| 3 | Alice gera R1, cifra com a chave pública de Bob e envia |
| 4 | Bob gera R2, cifra com a chave pública de Alice e envia |
| 5 | Ambos calculam `shift = (R1 XOR R2) % 26` independentemente |
| 6 | Alice cifra a mensagem com Cifra de César usando o shift |
| 7 | Bob decifra, processa (converte para maiúsculas) e responde cifrado |
| 8 | Alice decifra a resposta |

---

## Análise com Wireshark

Filtro a usar:

```
tcp.port == 1300
```

Para visualizar o conteúdo completo do protocolo, clique com o botão direito em qualquer pacote e selecione **Follow → TCP Stream**. O tráfego aparecerá em texto legível:

```json
{"e": 65537, "n": 28472...}        ← chave pública Bob
{"e": 65537, "n": 91234...}        ← chave pública Alice
{"R1_enc": 73924...}               ← R1 cifrado com RSA
{"R2_enc": 48175...}               ← R2 cifrado com RSA
{"msg": "Khoor"}                   ← mensagem cifrada com César
{"msg": "KHOOR"}                   ← resposta cifrada com César
```

Os pacotes `PSH, ACK` na listagem indicam cada envio de dados. Como as chaves RSA de 4096 bits são grandes, o TCP segmenta em múltiplos pacotes — o conteúdo completo é visto apenas no TCP Stream.

---

## Observações

- A geração de primos de 2048 bits pode levar entre 10 e 60 segundos dependendo da máquina — isso é esperado para RSA autoral sem bibliotecas otimizadas.
- O RSA é utilizado **somente** para proteger R1 e R2 durante a troca de chaves.
- As mensagens trafegam **somente** com Cifra de César, usando o shift derivado de R1 e R2.
- Todo o protocolo é implementado do zero, sem uso de bibliotecas criptográficas externas (`cryptography`, `rsa`, `pycryptodome` etc.).
