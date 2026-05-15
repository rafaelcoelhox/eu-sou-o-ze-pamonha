# eu sou o zé pamonha

Implementação em C para a Rinha de Backend 2026.

## Como rodar

```bash
docker compose up --build
```

A API fica disponível em `http://localhost:9999`.

## Build local

```bash
make
```

Os binários ficam em `build/`:

- `canjica`: API
- `carro-da-pamonha`: load balancer
- `build_ivf`: gerador do índice IVF

## Benchmarks por parte

```bash
make bench
```

Os benchmarks usam o mesmo código C dos binários de produção, apenas com o
`main()` desativado no include. Isso evita medir uma implementação paralela.
Eles são ignorados pelo Dockerfile/.dockerignore e não entram na imagem de
teste.

Exemplos:

```bash
# parser JSON puro
build/bench-json-parser resources/example-payloads.json 10000

# parser JSON + vetorização
build/bench-json-parser resources/example-payloads.json 10000 1

# seleção de upstream do load balancer
build/bench-lb 100000000 2

# geração de índice por etapas: load, init, kmeans e escrita opcional
build/bench-index-builder resources/references.json.gz 4096 50 /tmp/index.ivf

# só leitura/inicialização do gerador, sem k-means e sem escrita
build/bench-index-builder resources/references.json.gz 4096 0 -

# busca IVF/KNN usando payloads já parseados/vetorizados
build/bench-index-search /tmp/index.ivf resources/example-payloads.json 1000
```

Para uma validação rápida com arquivos de exemplo:

```bash
make bench-smoke
```

## Licença

MIT
