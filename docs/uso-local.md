# Usar o SecScan na sua máquina

O SecScan é uma ferramenta local. Você baixa o código, sobe um servidor na sua máquina e analisa arquivos ali. O relatório fica com você: achados, quality gate, SARIF e correções sugeridas.

Docker não entra nessa instalação. Não há imagem, `Dockerfile` nem `docker compose`. O que o processo precisa é Node.js 22 e npm.

Um site publicado (Vercel ou GitHub Pages) só mostra a interface. A auditoria de URL e a listagem de disco do `.gitignore` respondem quando o Express desta máquina está no ar.

## O que você vai ter no final

1. A interface aberta em `http://localhost:3000`.
2. Um scan de um arquivo que você enviou, ou do projeto de demonstração.
3. Um relatório no terminal, se você usar o CLI numa pasta do disco.

## O que precisa estar instalado

| Programa | Versão | Para quê |
|---|---|---|
| Node.js | 22 | Rodar o servidor e o CLI |
| npm | o que vem com o Node 22 | Instalar as dependências do repositório |
| Git | qualquer versão recente | Clonar o código |
| Navegador | Chrome, Firefox ou Edge atual | Abrir a interface |

Confira o Node antes de continuar:

```bash
node -v
npm -v
```

A primeira linha precisa começar com `v22`. Se aparecer `v18` ou `v20`, o `npm run dev` pode falhar porque o projeto usa APIs do Node 22. Instale o 22 em [nodejs.org](https://nodejs.org/) ou pelo gerenciador que você já usa (`nvm`, `fnm`, `volta`).

Docker, banco de dados, Redis e conta na Vercel ficam de fora.

## O que roda onde

| Ação | Onde acontece |
|---|---|
| Colar ou enviar código, ver achado, quality gate, grafo, SARIF | No navegador |
| Auditar uma URL pública | No Express local (`POST /api/url-ingest`) |
| Listar o `.gitignore` do disco | No Express local, e só em localhost |
| Mitigação com texto do Gemini | No Express local, se `GEMINI_API_KEY` existir |
| Mitigação sem essa chave | No motor local, dentro da própria tela |
| Consulta de pacote no OSV | No navegador, direto em `api.osv.dev` |
| Telas com selo LAB | Cenário de exemplo. Não varrem rede, host nem console |
| `node bin/secscan.js` | No terminal, sobre a pasta que você indicar |

## 1. Baixar o código

```bash
git clone https://github.com/saulofilho/secscan.git
cd secscan
```

Os comandos seguintes partem dessa pasta. O servidor lê o disco a partir do diretório em que você rodou `npm run dev`. Se você entrar em outra pasta, a listagem de `.gitignore` olha para o lugar errado.

## 2. Instalar as dependências

```bash
npm install
```

Isso cria `node_modules` e baixa Express, Vite, React e o resto declarado no `package.json`. A primeira vez pode levar um minuto. No fim, o npm imprime a árvore de pacotes e volta ao prompt, sem `ERR!`.

Se o repositório já tiver `package-lock.json` e você quiser a mesma árvore do CI:

```bash
npm ci
```

`npm ci` apaga `node_modules` e reinstala exatamente o que o lockfile trava. Use quando a instalação anterior tiver ficado pela metade.

## 3. Subir a interface

```bash
npm run dev
```

O script executa `tsx server.ts`. Esse processo faz duas coisas ao mesmo tempo: serve a interface e responde as rotas `/api`.

Quando estiver pronto, o terminal mostra uma linha nesta forma:

```text
SecScan AppSec Suite Server running on port 3000
```

Abra [http://localhost:3000](http://localhost:3000). A página de entrada do SecScan aparece. Deixe esse terminal aberto. `Ctrl+C` encerra o servidor e a página para de responder.

Se a porta 3000 já estiver ocupada, o processo encerra com `EADDRINUSE`. Feche o outro programa que usa a porta, ou encerre o `npm run dev` anterior que ficou aberto.

## 4. Rodar o primeiro scan na interface

1. Na página inicial, escolha **Carregar com Projeto Demo** se quiser um exemplo já preenchido. Para analisar código seu, entre na aplicação e envie os arquivos pelo seletor de arquivos do workspace.
2. Espere a barra de progresso chegar a 100%. O scan do texto que está na tela acontece no navegador. Ele não envia esse código para um serviço externo.
3. Abra o dashboard. O **Risk Score** é um número de 0 a 100. Zero achados deixa o score em 0. A conta é `100 × (1 − e^(−pontos/50))`, com crítico valendo 25, alto 15, médio 6, baixo 2 e info 0,5.
4. O rodapé diz que isto é uma ferramenta de teste e que telas de laboratório usam cenário de exemplo. Esse texto faz parte do produto.

Arquivos `.env`, `.pem` e chaves privadas são recusados no envio. O SecScan não quer que você suba um segredo real para a área de análise.

## 5. O que cada área faz nesse modo local

**Meu código.** Scanner, entropia, rotas, JS Miner, grafo, SCA, IaC, headers, JWT, classificador de SSRF, Dockerfile, política IAM e remediação. O resultado sai dos arquivos que estão no workspace.

**Laboratório.** IAST, DAST, Nmap, Nikto, WAF, firewall, DNS, SD-WAN, EDR, SOC e threat intel. O selo é LAB. A tela abre, o cenário é fixo, e nenhum pacote sai da máquina para varrer um alvo.

**Auditoria de URL.** Você informa um endereço `https://` público. O Express da sua máquina busca a página, recusa localhost, IP privado, metadata de nuvem e redirecionamento para esses destinos, e devolve os arquivos extraídos para o workspace. Isso só funciona com `npm run dev` (ou `npm start`) rodando. No site estático, a tela avisa que a rota não está no ar.

**SCA.** A tela lê `package.json` e `requirements.txt` do workspace. Em seguida o navegador pergunta ao OSV o nome e a versão de cada pacote. Se o OSV responder, os advisories entram no relatório e a licença continua a do catálogo local. Se a consulta falhar, o resultado fica nesse catálogo e o pacote ausente permanece `NOT_IN_CATALOG`.

**`.gitignore` no disco.** A aba de disco lista arquivos a partir da pasta do `npm run dev`, e só aceita a chamada vinda de localhost. Não defina `SECSCAN_API_TOKEN` para o uso local: a interface não envia esse header, e as rotas `/api` passariam a responder 401.

## 6. Chave do Gemini, se você quiser

A mitigação funciona sem chave, com o motor determinístico. Para pedir um texto ao Gemini:

```bash
cp .env.example .env
```

No `.env`, preencha só esta linha:

```bash
GEMINI_API_KEY=sua-chave
```

Salve, pare o servidor com `Ctrl+C` e suba de novo com `npm run dev`. O `server.ts` lê esse arquivo na subida. A chave fica no processo local. Não commite o `.env`.

Os anúncios (`VITE_ADSENSE_CLIENT_ID` e `VITE_ADSENSE_SLOT_ID`) podem ficar vazios. Vazios, a interface não desenha banner.

## 7. Scan pelo terminal

O CLI usa as mesmas regras padrão da interface (`src/lib/defaultRules.ts`). Ele lê arquivos do disco. Não abre o navegador e não precisa do servidor na porta 3000. Ainda precisa do `npm install`, porque o lançador usa o `tsx` instalado no projeto.

Na pasta de um código que você quer auditar:

```bash
node /caminho/para/secscan/bin/secscan.js .
```

Dentro do próprio repositório do SecScan, a pasta atual é o alvo:

```bash
node bin/secscan.js .
```

Esse comando, e o equivalente `node bin/secscan.js scan .`, aplicam as regras estáticas. Para um motor só:

```bash
node bin/secscan.js sca .
node bin/secscan.js iac .
node bin/secscan.js entropy .
node bin/secscan.js endpoints .
node bin/secscan.js sbom .
node bin/secscan.js compliance .
node bin/secscan.js dockerfile ./Dockerfile
node bin/secscan.js iam ./politica.json
node bin/secscan.js headers ./resposta.txt
node bin/secscan.js jwt "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0."
node bin/secscan.js ssrf "http://169.254.169.254/"
```

`sca` lê `package.json` e `requirements.txt` e não chama o OSV. `ssrf` classifica a URL e não envia pedido. `sbom` monta o CycloneDX e avisa que os hashes não são o digest dos arquivos. `headers` lê um arquivo de texto com linhas `Nome: valor`. Nmap, DAST, IAST, EDR, SOC e threat intel não têm subcomando.

A saída em tabela lista o resumo. `--format json` grava o objeto inteiro. O exit code fica 0 quando o comando termina a leitura.

Para falhar o comando se o score passar de 50:

```bash
node bin/secscan.js . --max-risk 50
```

Para falhar se existir achado crítico:

```bash
node bin/secscan.js . --fail-on critical
```

Para gravar SARIF 2.1.0:

```bash
node bin/secscan.js . --format sarif --output secscan-results.sarif
```

`--ignore` recebe globs separados por vírgula. `--rules arquivo.json` soma regras extras às regras padrão. `--help` imprime a lista completa.

## 8. Parar e subir de novo

No terminal do servidor, `Ctrl+C`. Para voltar:

```bash
npm run dev
```

`npm start` é o outro caminho: `npm run build` gera `dist/` e `npm start` executa `dist/server.cjs`. Use isso quando quiser o modo de produção na mesma máquina. Para o dia a dia, `npm run dev` basta.

## Quando algo não abre

**`node -v` não é 22.** Troque o Node e abra um terminal novo antes de `npm install`.

**`npm run dev` termina na hora.** Leia a última linha. `EADDRINUSE` significa porta 3000 ocupada. `Cannot find module` significa que o `npm install` não terminou nessa pasta.

**A página abre e a auditoria de URL diz que precisa do servidor.** O endereço não é `localhost:3000`, ou o terminal do `npm run dev` já foi encerrado. O site estático não executa essa rota.

**A mitigação não cita o Gemini.** Falta `GEMINI_API_KEY` no `.env`, ou o servidor não foi reiniciado depois de salvar o arquivo. A tela ainda mostra a correção do motor local.
