.PHONY: install run serve test docs docker docker-test clean

install:            ## Instala dependencias (incluye pytest)
	pip install -r requirements-dev.txt

run:                ## Pipeline completo: generar → detectar → casos
	python -m soc_lab all

serve: run          ## Pipeline completo + dashboard en http://127.0.0.1:8000
	python -m soc_lab serve

test:               ## Ejecuta la suite de pruebas
	python -m pytest

docs:               ## Regenera la documentación de reglas desde los YAML
	python -m soc_lab docs

docker:             ## Todo en Docker: http://localhost:8000
	docker compose up --build

docker-test:        ## Pruebas dentro del contenedor
	docker compose run --rm --build tests

clean:
	rm -rf data .pytest_cache
