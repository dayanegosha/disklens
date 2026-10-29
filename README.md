# .disklens

локальный анализатор диска: крупные файлы, тяжёлые папки и точные дубликаты.

работает на Python 3.11+ без сторонних зависимостей. ничего не удаляет и не отправляет в сеть.

## запуск

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install .
disklens ~/Downloads
```

## лицензия

[MIT](LICENSE)
