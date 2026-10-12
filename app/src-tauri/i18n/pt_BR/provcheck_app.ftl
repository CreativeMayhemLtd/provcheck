# Mensagens da GUI do provcheck-app, portugues do Brasil. Apenas frases completas
# voltadas ao usuario, devolvidas a GUI como texto ApiResult ok/err, sao localizadas
# aqui; os diagnosticos tecnicos { $err }/caminho de log e os rotulos de erro IPC
# permanecem em ingles. Termos de marca e tecnicos (provcheck, provcheck-kit, Backfire,
# Mellin, C2PA, atproto, LOCALAPPDATA, BACKFIRE_PY, Yubikey, PIV PIN, DID, flags, nomes
# de arquivo) permanecem literais em cada idioma.

## Aba de imagem com chave do Backfire (backfire_read + install_backfire).
backfire-read-needs-key = E necessaria uma chave para ler uma marca do Backfire.
backfire-folder-unresolved = Nao foi possivel resolver uma pasta do Backfire com permissao de escrita (LOCALAPPDATA nao definido).
backfire-ready-bundled = Backfire esta pronto (leitor incluido presente). Digite uma chave e solte uma imagem.
backfire-files-missing = Arquivos do Backfire nao encontrados para instalacao. Reinstale o provcheck, ou defina BACKFIRE_PY.
backfire-ready = Backfire esta pronto. Digite uma chave e solte uma imagem.

## Aba de marcas com chave do Mellin (mellin_read).
mellin-needs-secret-and-work-id = Um arquivo secreto e um work id sao necessarios para ler um serial do Mellin.
mellin-secret-file-missing = O arquivo secreto escolhido nao existe (ou nao pode ser lido).

## Abas Sign e Keys: avisos de limite de capacidade da GUI devolvidos como erros ApiResult.
identity-already-exists = ja existe uma identidade neste diretorio de dados; passe force=true para regera-la (isso torna orfaos todos os registros atproto publicados anteriormente)
rotate-yubikey-unsupported = A rotacao pela GUI de uma identidade baseada em Yubikey ainda nao e suportada. Execute `provcheck-kit init --yubikey --force` em um terminal, e depois volte aqui para publicar e revogar.
rotate-agefile-unsupported = A rotacao pela GUI de identidades baseadas em arquivo age ainda nao esta conectada. Use `provcheck-kit rotate` em um terminal.
sign-keychain-only = A assinatura pela GUI atualmente suporta apenas identidades do chaveiro do sistema operacional. Use `provcheck-kit sign` na CLI para identidades baseadas em arquivo age.
sign-yubikey-unsupported = A assinatura pela GUI de identidades baseadas em Yubikey chega na v0.5.0 P3 + P4. Por enquanto, assine via `provcheck-kit sign` em um terminal: o kit solicita o PIN do PIV a cada assinatura.
