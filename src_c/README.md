# Layout C

Os binarios de producao continuam em arquivos unicos:

- `api.c`: API, parser de payload, vetorizacao, busca IVF/KNN e loop epoll.
- `lb.c`: load balancer TCP e handoff de FDs para as APIs.
- `build_ivf.c`: leitura das referencias, k-means e escrita do indice IVF.

Essa organizacao preserva o build em uma unidade de compilacao por binario,
que ajuda o compilador a otimizar o caminho quente sem depender de LTO.

Os benchmarks ficam em `bench/`. Eles incluem os mesmos arquivos de producao
com `RINHA_API_NO_MAIN`, `RINHA_LB_NO_MAIN` ou `RINHA_BUILD_IVF_NO_MAIN`, de
modo que cada benchmark mede a implementacao real e nao uma copia adaptada.
