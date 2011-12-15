/*
 * JavaScript MD5 Test 1.0
 * https://github.com/blueimp/JavaScript-MD5
 *
 * Copyright 2011, Sebastian Tschan
 * https://blueimp.net
 *
 * Licensed under the MIT license:
 * http://www.opensource.org/licenses/MIT
 */

/*global require */

(function ($) {
    'use strict';

    var lifecycle = {
            setup: function () {},
            teardown: function () {}
        },
        nodeQunit = {
            setup: function () {},
            teardown: function () {}
        };

    if (!$.module) {
        // Node.js QUnit compatible Testrunner:
        nodeQunit = require('./node-qunit');
        $.module = nodeQunit.module;
        $.test = nodeQunit.test;
        $.strictEqual = nodeQunit.assert.strictEqual;
        $.md5 = require('../md5').md5;
    }

    nodeQunit.setup();

    $.module('Hex-encoded MD5', lifecycle);

    $.test('Creating hex-encoded MD5 hash of an ASCII value', function () {
        $.strictEqual(
            $.md5('value'),
            '2063c1608d6e0baf80249c42e2be5804'
        );
    });

    $.test('Creating hex-encoded MD5 hash of an UTF-8 value', function () {
        $.strictEqual(
            $.md5('日本'),
            '4dbed2e657457884e67137d3514119b3'
        );
    });

    $.module('Hex-encoded HMAC-MD5', lifecycle);

    $.test('Creating hex-encoded HMAC-MD5 hash of an ASCII value and key', function () {
        $.strictEqual(
            $.md5('value', 'key'),
            '01433efd5f16327ea4b31144572c67f6'
        );
    });

    $.test('Creating hex-encoded HMAC-MD5 hash of an UTF-8 value and key', function () {
        $.strictEqual(
            $.md5('日本', '日本'),
            'c78b8c7357926981cc04740bd3e9d015'
        );
    });

    $.module('Raw MD5', lifecycle);

    $.test('Creating raw MD5 hash of an ASCII value', function () {
        $.strictEqual(
            $.md5('value', null, true),
            ' c\xc1`\x8dn\x0b\xaf\x80$\x9cB\xe2\xbeX\x04'
        );
    });

    $.test('Creating raw MD5 hash of an UTF-8 value', function () {
        $.strictEqual(
            $.md5('日本', null, true),
            'M\xbe\xd2\xe6WEx\x84\xe6q7\xd3QA\x19\xb3'
        );
    });

    $.module('Raw HMAC-MD5', lifecycle);

    $.test('Creating raw HMAC-MD5 hash of an ASCII value and key', function () {
        $.strictEqual(
            $.md5('value', 'key', true),
            '\x01C>\xfd_\x162~\xa4\xb3\x11DW,g\xf6'
        );
    });

    $.test('Creating raw HMAC-MD5 hash of an UTF-8 value and key', function () {
        $.strictEqual(
            $.md5('日本', '日本', true),
            '\xc7\x8b\x8csW\x92i\x81\xcc\x04t\x0b\xd3\xe9\xd0\x15'
        );
    });

    nodeQunit.teardown();

}(this));
