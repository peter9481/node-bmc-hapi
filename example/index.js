import 'babel-polyfill';
import fs from 'fs';
import path from 'path';
import { inspect } from 'util';
import bmcHapi from '../src';

const protocol = 'https';
const conf = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../../conf.json'), 'utf-8'));

// Detect device
bmcHapi.detectDev(conf.protocol, conf.ip, 'ThinkServer Management Module').then((args) => {
  let {cc, isDev} = args
  console.log('Detect Device: ' + cc + ', ' + isDev);
});

// Get some data => Use pure Promise
bmcHapi.login(conf.protocol, conf.ip, conf.account, conf.password).then((args) => {

  let {cc, cookie, token} = args;
  console.log('Session 1 => Login: ' + cc + ', ' + cookie + ', ' + token);

  // Get role
  bmcHapi.getRole(conf.protocol, conf.ip, cookie, token).then((args) => {
    let {cc, userName, userPriv} = args;
    console.log('Get Role: ' + cc + ', ' + userName + ', ' + userPriv);
  }).catch((err) => {
    console.log('Get Role: ' + err);
  });

  // Get BMC FW Information
  bmcHapi.getBmcFwInfo(conf.protocol, conf.ip, cookie, token).then((args) => {
    let {cc, version, buildTime} = args;
    console.log('Get BMC FW Info: ' + cc + ', ' + version + ', ' + buildTime);
  }).catch((err) => {
    console.log('Get BMC FW Info: ' + err);
  });

  // Get BIOS FW Information
  bmcHapi.getBiosFwInfo(conf.protocol, conf.ip, cookie, token).then((args) => {
    let {cc, version} = args;
    console.log('Get BIOS FW Info: ' + cc + ', ' + version);
  }).catch((err) => {
    console.log('Get BIOS FW Info: ' + err);
  });

  // Get SSL Certificate
  bmcHapi.getSslCert(conf.protocol, conf.ip, cookie, token).then((args) => {
    let {cc, certInfo} = args;
    console.log('Get SSL Cert: ' + cc + ', ' + inspect(certInfo));
  }).catch((err) => {
    console.log('Get SSL Cert: ' + err);
  });

  return bmcHapi.logout(conf.protocol, conf.ip, cookie, token);

}).catch((err) => {
  console.log('Login: ' + err);
}).then((cc) => {
  console.log('Logout: ' + cc);
}).catch((err) => {
  console.log('Logout: ' + err);
});

// Upload SSL Cert => use Async/Await
(async function uploadSsl(protocol, ip, account, password) {

  try {
    // Login
    let {cc, cookie, token} = await bmcHapi.login(protocol, ip, account, password);
    console.log('Session 2 => Login: ' + cc + ', ' + cookie + ', ' + token);

    // Upload SSL Cert
    cc = await bmcHapi.uploadSslCert(protocol, ip, cookie, token, (__dirname + '/../../cert/web-cert.pem'));
    console.log('Upload SSL Cert: ' + cc);

    // Upload SSL Key
    cc = await bmcHapi.uploadSslKey(protocol, ip, cookie, token, (__dirname + '/../../cert/web-certkey.pem'));
    console.log('Upload SSL Key: ' + cc);

    // Validate SSL
    cc = await bmcHapi.validateSsl(protocol, ip, cookie, token);
    console.log('Validate SSL: ' + cc);

    // Restart HTTPS and logout
    cc = await bmcHapi.restartHttps(protocol, ip, cookie, token);
    console.log('Restart HTTPS: ' + cc);

  } catch (err) {
    console.log(err);
  }
}(conf.protocol, conf.ip, conf.account, conf.password));

