# Saida em tempo de execucao do provcheck-cli, portugues do Brasil (fonte de verdade
# em ingles). Apenas a saida legivel por humanos e localizada; a saida --json e os
# codigos de saida nunca sao localizados. Os marcadores { $name } sao preenchidos no
# ponto de chamada; mantenha-os intactos nas traducoes. Termos de marca e tecnicos
# (provcheck, C2PA, Backfire, Mellin, BUSL, Apache-2.0, JSON, PowerShell, bash, flags,
# nomes de arquivo) permanecem literais em cada idioma.

## Bloco forense de audio com chave do Mellin (print_mellin_human).
mellin-header = Mellin (experimental, serial forense de audio com chave):
mellin-serial-full = serial:   { $serial } (todos os 64 bits recuperados, votos minimos de bit { $votes })
mellin-serial-partial = serial:   nao recuperado por completo ({ $bits }/64 bits, votos minimos de bit { $votes })
mellin-erasures = apagamentos: { $pct }% das posicoes
mellin-expected-match = esperado: CORRESPONDE
mellin-expected-no-match = esperado: NAO CORRESPONDE

## Bloco de marca d'agua de imagem com chave do Backfire (print_backfire_human).
backfire-header = Backfire (experimental, marca d'agua de imagem com chave):
backfire-mark-valid = marca:   VALIDA (id { $id }, margem { $margin })
backfire-mark-none = marca:   nao detectada (margem { $margin })
backfire-tamper-detected = adulteracao: NOTCH DE BANDA DETECTADO (estatistica { $stat }): a imagem muito provavelmente sofreu um ataque de notch
backfire-tamper-none = adulteracao: nenhuma (estatistica de notch de banda { $stat })

## Configuracao do Backfire (--install-backfire).
backfire-folder-not-found = provcheck: nao foi possivel localizar a pasta backfire. Defina BACKFIRE_PY apontando para backfire.py, ou execute a partir de um diretorio que contenha backfire/backfire.py.
backfire-ps1-not-found = provcheck: setup_backfire.ps1 nao encontrado em { $dir }
backfire-sh-not-found = provcheck: setup_backfire.sh nao encontrado em { $dir }
backfire-setup-start = Configurando o ambiente de leitura do Backfire (uma unica vez). Isso baixa um Python autocontido.
backfire-setup-ready = Backfire esta pronto. Verifique uma imagem marcada com:  provcheck --backfire-read --backfire-key <KEY> <IMAGE>
backfire-setup-exit-status = provcheck: a configuracao do Backfire terminou com status { $status }
backfire-setup-run-failed = provcheck: nao foi possivel executar o script de configuracao do Backfire ({ $err }). Ele precisa do PowerShell no Windows, ou do bash no Linux/macOS.

## Instalacao de modelos (--install-models).
install-models-start = Instalando { $count } arquivo(s) de modelo de deteccao de marca d'agua ({ $mb } MB no total).
install-models-item = { $family }/{ $variant } ({ $mb } MB) ...
install-models-ok = ok
install-models-item-failed = FALHOU: { $err }
install-models-done = Todos os modelos foram instalados. A deteccao de marca d'agua esta pronta.
install-models-summary-failed = provcheck: { $count } modelo(s) falharam ao instalar (veja acima).

## Caminho principal de verificacao: erros, avisos e dicas.
require-attested-needs-identity = provcheck: --require-attested precisa de --bsky-handle, --did, ou --auto-identity
trust-store-read-failed = provcheck: nao foi possivel ler o trust store '{ $path }': { $err }
auto-identity-no-assertion = provcheck: --auto-identity foi solicitado, mas o arquivo nao carrega nenhuma assercao app.provcheck.identity. Assine primeiro com `provcheck-kit sign --embed-identity`, ou passe --bsky-handle / --did diretamente.
backfire-needs-key = provcheck: --backfire-read precisa de --backfire-key
backfire-experimental-notice = provcheck: Backfire e EXPERIMENTAL e licenciado sob BUSL (gratuito para uso nao comercial), separado do nucleo Apache-2.0. Ele verifica uma marca com chave que voce incorporou e sinaliza adulteracao por notch de banda; a robustez e especifica por imagem.
backfire-read-failed = provcheck: falha na leitura do backfire: { $err }
mellin-needs-args = provcheck: --mellin-read precisa de --mellin-secret-file e --mellin-work-id
mellin-experimental-notice = provcheck: Mellin e EXPERIMENTAL e licenciado sob BUSL (gratuito para uso nao comercial), separado do nucleo Apache-2.0. Ele le um serial com chave por copia que voce incorporou; sem o seu secret e o seu work id, nao ha nada para ler.
mellin-read-failed = provcheck: falha na leitura do mellin: { $err }
json-serialize-failed = provcheck: falha ao serializar JSON: { $err }
hint-models-missing = [dica] { $count } modelo(s) de deteccao de marca d'agua nao estao instalados, entao essas linhas mostram "not installed". Ative toda a deteccao com:  provcheck --install-models  (uma unica vez, { $mb } MB). A verificacao C2PA nao precisa deles.
hint-claims-identity = [dica] o arquivo reivindica a identidade { $who }. Execute novamente com --auto-identity para verifica-la contra os registros de chave de assinatura publicados.
