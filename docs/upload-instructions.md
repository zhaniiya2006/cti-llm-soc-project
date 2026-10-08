# Загрузка исправленного проекта на GitHub

Репозиторий: [zhaniiya2006/cti-llm-soc-project](https://github.com/zhaniiya2006/cti-llm-soc-project).

1. Распакуй ZIP через «Извлечь всё». Открой папку, где одновременно видны `README.md`, `Week1`, `week2`, `week3`, `week4`, `docs`, `tests`, `tools`, `.github`, `.gitignore` и файлы `requirements-*.txt`.
2. Войди в GitHub как `zhaniiya2006`. Открой репозиторий, вкладку **Code**, ветку **main** и корень списка файлов.
3. Выбери **Add file → Upload files**. Выдели всё содержимое распакованной папки (Ctrl+A) и перетащи его в область загрузки. Сохраняй каталоги целиком: отчёт должен оказаться в `week3/week3-report.md`, данные в `week3/data`, картинки в `week3/images`.
4. Проверь список перед отправкой: пути начинаются с `Week1/`, `week2/`, `week3/` и других каталогов проекта. Дополнительной внешней папки `cti-llm-soc-project-audited/` быть не должно. Всего в архиве 46 файлов.
5. Укажи сообщение `Update audited weeks 1-4 and evidence`. Выбери **Commit directly to main**, если доступно, и нажми **Commit changes**. Если требуется новая ветка, создай её, открой pull request и после проверки объедини его в main. Файлы в другой ветке ещё не обновляют main.
6. После загрузки открой `week2/week2` на GitHub. Это старый каталог изображений; новые находятся в `week2/images`. Убедись, что новый отчёт открывает все шесть картинок из нового каталога. Затем в старом каталоге выбери меню **⋯ → Delete directory**, проверь список удаляемых файлов и сохрани удаление. Не удаляй основную папку `week2`.
7. Открой корневой README и ссылки на отчёты четырёх недель. В Week 3 должны отображаться три изображения, включая настоящий `03-misp-event-live.jpg`. Проверь открытие CSV, JSON и Sigma-правила.

По последней проверке main (`53d74c5`) Week 3 уже лежит в правильном каталоге. Старая проблема файлов Week 3 в корне устранена владельцем; повторное удаление этих файлов не требуется.

Загружай извлечённые файлы и каталоги. GitHub не распаковывает загруженный ZIP в структуру репозитория.

Порядок загрузки и удаления каталогов проверен по [GitHub Docs: upload](https://docs.github.com/en/repositories/working-with-files/managing-files/adding-a-file-to-a-repository) и [GitHub Docs: delete directory](https://docs.github.com/en/repositories/working-with-files/managing-files/deleting-files-in-a-repository).
