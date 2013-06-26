.PHONY: default js

default: js

js:
	node_modules/.bin/uglifyjs js/md5.js -c -m -o js/md5.min.js
