dev:
	cd license-server && npx wrangler dev

test: test-rlib test-server test-nodelib
	@echo 'All tests passed'

test-rlib:
	cd license-lib && cargo test

test-nodelib:
	yarn run build:debug && yarn run test

test-server:
	cd license-server && cargo test

build:
	yarn run build

lint:
	yarn run lint

install:
	yarn

deploy:
	cd license-server && npx wrangler deploy