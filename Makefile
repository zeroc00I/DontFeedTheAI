# DontFeedTheAI — Makefile
# All logic lives in wizard.py. These are Unix convenience aliases only.
# Windows users: run python3 wizard.py <command> directly.

.PHONY: setup wizard deploy sync connect tunnel test improve benchmark \
        docker-up docker-down vault-stats vault-clear clean install

setup:
	python3 wizard.py setup

wizard:
	python3 wizard.py

deploy:
	python3 wizard.py deploy

sync:
	python3 wizard.py sync

connect:
	python3 wizard.py connect

tunnel:
	python3 wizard.py tunnel

install:
	python3 wizard.py install

test:
	python3 wizard.py test

test-integration:
	python3 wizard.py test --integration

improve:
	python3 wizard.py improve --cycles 3

benchmark:
	python3 wizard.py benchmark

docker-up:
	python3 wizard.py docker up

docker-down:
	python3 wizard.py docker down

vault-stats:
	python3 wizard.py vault stats

vault-clear:
	python3 wizard.py vault clear

clean:
	python3 wizard.py clean
