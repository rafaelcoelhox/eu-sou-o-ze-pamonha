# Benchmarks C

Estes harnesses incluem os arquivos de producao com `RINHA_*_NO_MAIN`.
Assim cada benchmark chama as mesmas funcoes `static` usadas pelos binarios
finais, sem criar uma segunda implementacao para medir.

- `bench_json_parser.c`: `parse_json()` isolado, com opcao de incluir `vectorize()`.
- `bench_index_search.c`: `knn5_search()` isolado depois de parsear/vetorizar os payloads uma vez.
- `bench_index_builder.c`: mede `load_references()`, inicializacao, iteracoes de k-means e escrita IVF.
- `bench_lb.c`: mede o hot path de escolha de upstream do load balancer.
