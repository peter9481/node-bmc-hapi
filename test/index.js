import fs from 'fs';
import path from 'path';
import bmcHapi from '../src';
import { inspect } from 'util';
import chai, { assert, expect } from 'chai';

const conf = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../../conf.json'), 'utf-8'));

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

    it('should define getSslCert method', () => {
      assert.isDefined(bmcHapi.getSslCert, ('Get SSL Cert method has been defined'));
    });

    it('should define uploadSslCert method', () => {
      assert.isDefined(bmcHapi.uploadSslCert, ('Upload SSL Cert method has been defined'));
    });

    it('should define uploadSslKey method', () => {
      assert.isDefined(bmcHapi.uploadSslKey, ('Upload SSL Key method has been defined'));
    });

    it('should define validateSsl method', () => {
      assert.isDefined(bmcHapi.validateSsl, ('Validate SSL method has been defined'));
    });

    it('should define restartHttps method', () => {
      assert.isDefined(bmcHapi.restartHttps, ('Restart HTTPS method has been defined'));
    });
  });

  describe('worked or not...', () => {

    let gCookie, gToken;

    beforeEach((done) => {
      bmcHapi.login(conf.protocol, conf.ip, conf.account, conf.password).then((args) => {
        let {cc, cookie, token} = args;
        gCookie = cookie;
        gToken = token;
        done();
      });
    });
    afterEach((done) => {
      bmcHapi.logout(conf.protocol, conf.ip, gCookie, gToken).then((cc) => {
        done();
      });
    });

    it('get role', () => {
      return bmcHapi.getRole(conf.protocol, conf.ip, gCookie, gToken).then((args) => {
        let {cc, userName, userPriv} = args;
        expect(cc).to.equal(0);
        expect(userName).to.not.be.null;
        expect(userName).to.not.be.undefined;
        expect(userPriv).to.not.be.null;
        expect(userPriv).to.not.be.undefined;
        expect(userPriv).to.be.within(1, 5);
      });
    });

    it('get bmc firmware information', () => {
      return bmcHapi.getBmcFwInfo(conf.protocol, conf.ip, gCookie, gToken).then((args) => {
        let {cc, version, buildTime} = args;
        expect(cc).to.equal(0);
        expect(version).to.not.be.null;
        expect(version).to.not.be.undefined;
        expect(buildTime).to.not.be.null;
        expect(buildTime).to.not.be.undefined;
      });
    });

    it('get bios firmware information', () => {
      return bmcHapi.getBiosFwInfo(conf.protocol, conf.ip, gCookie, gToken).then((args) => {
        let {cc, version} = args;
        expect(cc).to.equal(0);
        expect(version).to.not.be.null;
        expect(version).to.not.be.undefined;
      });
    });

    it('get SSL Cert information', () => {
      return bmcHapi.getSslCert(conf.protocol, conf.ip, gCookie, gToken).then((args) => {
        let {cc, certInfo} = args;
        expect(cc).to.equal(0);
        expect(certInfo).to.not.be.null;
        expect(certInfo).to.not.be.undefined;
        expect(certInfo).to.have.ownProperty('FromCommonName');
        expect(certInfo).to.have.ownProperty('FromOrganization');
        expect(certInfo).to.have.ownProperty('FromOrgUnit');
        expect(certInfo).to.have.ownProperty('FromCity');
        expect(certInfo).to.have.ownProperty('FromState');
        expect(certInfo).to.have.ownProperty('FromCountry');
        expect(certInfo).to.have.ownProperty('FromEmailID');
      });
    });

  });
});
