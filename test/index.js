require('babel-register');

const fs       = require('fs');
const path     = require('path');
const bmcHapi  = require('../lib');
const chai     = require('chai'),
      assert   = require('chai').assert,
      expect   = require('chai').expect;

const conf = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../conf.json'), 'utf-8'));

describe('bmcHapi', () => {

  describe('defined or not...', () => {

    it('should define login method', () => {
      assert.isDefined(bmcHapi.login, ('Login method has been defined'));
    });

    it('should define logout method', () => {
      assert.isDefined(bmcHapi.logout, ('Login method has been defined'));
    });

    it('should define getRole method', () => {
      assert.isDefined(bmcHapi.getRole, ('Get Role method has been defined'));
    });

    it('should define getBmcFwInfo method', () => {
      assert.isDefined(bmcHapi.getBmcFwInfo, ('Get BMC FW Info method has been defined'));
    });

    it('should define getBiosFwInfo method', () => {
      assert.isDefined(bmcHapi.getBiosFwInfo, ('Get BIOS FW Info method has been defined'));
    });
  });

  describe('worked or not...', () => {

    'use strict';
    let gCookie, gToken;

    beforeEach((done) => {
      bmcHapi.login(conf.protocol, conf.ip, conf.account, conf.password, (err, cc, cookie, token) => {
        gCookie = cookie;
        gToken = token;
        done();
      });
    });
    afterEach((done) => {
      bmcHapi.logout(conf.protocol, conf.ip, gCookie, gToken, (err, cc) => {
        done();
      });
    });

    it('get role', () => {
      bmcHapi.getRole(conf.protocol, conf.ip, gCookie, gToken, (err, cc, userName, userPriv) => {
        expect(cc).to.equal(0);
        expect(userName).to.not.be.null;
        expect(userName).to.not.be.undefined;
        expect(userPriv).to.not.be.null;
        expect(userPriv).to.not.be.undefined;
        expect(userPriv).to.be.within(1, 5);
      });
    });

    it('get bmc firmware information', () => {
      bmcHapi.getBmcFwInfo(conf.protocol, conf.ip, gCookie, gToken, (err, cc, version, buildTime) => {
        expect(cc).to.equal(0);
        expect(version).to.not.be.null;
        expect(version).to.not.be.undefined;
        expect(buildTime).to.not.be.null;
        expect(buildTime).to.not.be.undefined;
      });
    });

    it('get bios firmware information', () => {
      bmcHapi.getBiosFwInfo(conf.protocol, conf.ip, gCookie, gToken, (err, cc, version) => {
        expect(cc).to.equal(0);
        expect(version).to.not.be.null;
        expect(version).to.not.be.undefined;
      });
    });

  });
});
