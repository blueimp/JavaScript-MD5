.PHONY: js

js:
	uglifyjs -nc md5.js > md5.min.js
