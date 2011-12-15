/*
 * Node.js QUnit compatible Testrunner 1.0
 * https://github.com/blueimp/JavaScript-MD5
 *
 * Copyright 2011, Sebastian Tschan
 * https://blueimp.net
 *
 * Licensed under the MIT license:
 * http://www.opensource.org/licenses/MIT
 */

/*global require, console, process */

(function ($) {
    'use strict';

    var util = require('util'),
        colors = {
            info: 37,
            pass: 33,
            fail: 31
        },
        passed = 0,
        failed = 0,
        lifecycle = {
            setup: function () {},
            teardown: function () {}
        },
        log = function (msg, level) {
            level = level || 'info';
            console.log('\x1B[' + colors[level] +
                'm[' +  level.toUpperCase() + '] ' + msg + '\x1B[0m');
        };
    $.module = function (msg, cycle) {
        log('Module: ' + msg);
        lifecycle = cycle;
    };
    $.test = function (msg, func) {
        lifecycle.setup();
        var level;
        try {
            func();
            level = 'pass';
            passed += 1;
        } catch (e) {
            msg += ': ' + util.inspect(e);
            level = 'fail';
            failed += 1;
        }
        log(msg, level);
        lifecycle.teardown();
    };
    $.setup = function () {
        log('Test started...');
    };
    $.teardown = function () {
        log('Test finished.');
        if (failed) {
            log('Failed ' + failed + ' of ' + (passed + failed) + ' tests.', 'fail');
            process.exit(1);
        } else {
            log('Passed ' + passed + ' of ' + (passed + failed) + ' tests.', 'pass');
        }
    };
    $.assert = require('assert');
}(this));
