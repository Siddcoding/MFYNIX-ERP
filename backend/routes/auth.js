const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const db = require('../db');
const { signToken, requireAuth } = require('../middleware/auth');
const totp = require('../services/totp');
const { checkPassword } = require('../services/passwords');
const messaging = require('../services/messaging');

const MAX_FAILED_LOGINS = Number(process.env.MAX_FAILED_LOGINS) || 5;
const LOCK_MINUTES = Number(process.env.LOCK_MINUTES) || 15;

const router = express.Router();

// Per-IP request caps. Configurable so an automated test run (which signs in
// many times from one address) is not throttled; production keeps the defaults.
const RATE_MAX = Number(process.env.AUTH_RATE_MAX) || 10;

const resetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: RATE_MAX,
  message: { error: 'Too many reset attempts. Try again in 15 minutes.' }
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: RATE_MAX,
  message: { error: 'Too many login attempts. Try again in 15 minutes.' }
});

function logAudit({ companyId, branchId, userId, action, entityType, entityId, details, ip }) {
  db.prepare(
    `INSERT INTO AuditLog (CompanyID, BranchID, UserID, Action, EntityType, EntityID, Details, IPAddress)
     VALUES (?,?,?,?,?,?,?,?)`
  ).run(companyId, branchId, userId, action, entityType || null, entityId || null, details || null, ip || null);
}

// List companies -> branches, for the login screen's Company/Branch selectors
router.get('/companies', (req, res) => {
  const companies = db.prepare('SELECT CompanyID, CompanyName FROM Company WHERE IsActive = 1').all();
  res.json(companies);
});

router.get('/branches/:companyId', (req, res) => {
  const branches = db.prepare(
    'SELECT BranchID, BranchName, BranchCode, IsHeadOffice FROM Branch WHERE CompanyID = ? AND IsActive = 1'
  ).all(req.params.companyId);
  res.json(branches);
});

router.post('/login', loginLimiter, (req, res) => {
  const { username, password, companyId, rememberMe } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const user = db.prepare(
    `SELECT u.*, r.RoleName, b.BranchName, b.BranchCode, c.CompanyName
     FROM Users u
     JOIN Role r ON r.RoleID = u.RoleID
     JOIN Company c ON c.CompanyID = u.CompanyID
     LEFT JOIN Branch b ON b.BranchID = u.BranchID
     WHERE u.UserName = ?`
  ).get(username);

  if (!user) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  if (user.Status !== 'Active') {
    return res.status(401).json({ error: 'This account has been deactivated. Contact your administrator.' });
  }
  if (companyId && Number(companyId) !== user.CompanyID) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  // Lockout (ROL-01): after repeated failures the account refuses sign-in for a
  // while, even with the right password, so guessing cannot be automated.
  if (user.LockedUntil && new Date(user.LockedUntil).getTime() > Date.now()) {
    const mins = Math.ceil((new Date(user.LockedUntil).getTime() - Date.now()) / 60000);
    logAudit({ companyId: user.CompanyID, branchId: user.BranchID, userId: user.UserID, action: 'LOGIN_BLOCKED_LOCKED', ip: req.ip });
    return res.status(423).json({ error: `Too many failed attempts. This account is locked for another ${mins} minute${mins === 1 ? '' : 's'}.` });
  }
  const ok = bcrypt.compareSync(password, user.PasswordHash);
  if (!ok) {
    const failed = (user.FailedLogins || 0) + 1;
    if (failed >= MAX_FAILED_LOGINS) {
      const until = new Date(Date.now() + LOCK_MINUTES * 60000).toISOString();
      db.prepare('UPDATE Users SET FailedLogins = 0, LockedUntil = ? WHERE UserID = ?').run(until, user.UserID);
      logAudit({ companyId: user.CompanyID, branchId: user.BranchID, userId: user.UserID, action: 'ACCOUNT_LOCKED', details: `${failed} failed sign-ins`, ip: req.ip });
    } else {
      db.prepare('UPDATE Users SET FailedLogins = ? WHERE UserID = ?').run(failed, user.UserID);
    }
    logAudit({ companyId: user.CompanyID, branchId: user.BranchID, userId: user.UserID, action: 'LOGIN_FAILED', ip: req.ip });
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  // ROL-02: second factor for accounts that have it switched on.
  if (user.TotpEnabled) {
    const code = String(req.body.totp || req.body.otp || '').trim();
    if (!code) {
      return res.status(401).json({ error: 'Enter the 6-digit code from your authenticator app', totpRequired: true });
    }
    let good = totp.verify(user.TotpSecret, code);
    if (!good && /^[0-9a-f]{10}$/i.test(code)) {
      // A recovery code is single-use: accept it, then burn it.
      let codes = [];
      try { codes = JSON.parse(user.RecoveryCodesJson || '[]'); } catch (e) { codes = []; }
      const idx = codes.indexOf(code.toLowerCase());
      if (idx >= 0) { good = true; codes.splice(idx, 1); db.prepare('UPDATE Users SET RecoveryCodesJson = ? WHERE UserID = ?').run(JSON.stringify(codes), user.UserID); }
    }
    if (!good) {
      logAudit({ companyId: user.CompanyID, branchId: user.BranchID, userId: user.UserID, action: 'LOGIN_2FA_FAILED', ip: req.ip });
      return res.status(401).json({ error: 'That code is not valid', totpRequired: true });
    }
  }

  db.prepare('UPDATE Users SET LastLogin = datetime(\'now\'), LastActivity = datetime(\'now\'), FailedLogins = 0, LockedUntil = NULL WHERE UserID = ?').run(user.UserID);
  logAudit({ companyId: user.CompanyID, branchId: user.BranchID, userId: user.UserID, action: 'LOGIN', ip: req.ip });

  const token = signToken(user, { rememberMe: !!rememberMe });
  res.json({
    token,
    user: {
      userId: user.UserID,
      userName: user.UserName,
      fullName: user.FullName,
      role: user.RoleName,
      companyId: user.CompanyID,
      companyName: user.CompanyName,
      branchId: user.BranchID,
      branchName: user.BranchName || 'All Branches (Head Office)',
      mustChangePassword: !!user.MustChangePassword,
      totpEnabled: !!user.TotpEnabled
    }
  });
});

router.get('/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// ---- Forgot / reset password ----
// PLT-03: the reset token is sent ONLY to the user's registered email address.
// It is never returned in the response and never shown on screen. If no email
// provider is configured the message is recorded in the delivery log as
// "NotSent" (the token itself is hidden there) and an administrator can set a
// temporary password from Branches & Users instead.

function publicBaseUrl(req) {
  return (process.env.PUBLIC_URL || `${req.protocol}://${req.get('host')}`).replace(/\/$/, '');
}

router.post('/forgot-password', resetLimiter, async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Username is required' });

  const user = db.prepare('SELECT UserID, CompanyID, BranchID, Email, FullName, UserName, Status FROM Users WHERE UserName = ?').get(username);

  // Always respond the same way whether or not the user exists, so this
  // endpoint can't be used to enumerate valid usernames.
  const genericResponse = { message: 'If that account exists and has an email address, a reset code has been sent to it.' };
  if (!user || user.Status !== 'Active') return res.json(genericResponse);

  const resetToken = crypto.randomBytes(24).toString('hex');
  const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
  const expiry = new Date(Date.now() + 15 * 60 * 1000).toISOString(); // 15 minutes

  db.prepare('UPDATE Users SET ResetTokenHash = ?, ResetTokenExpiry = ? WHERE UserID = ?')
    .run(resetTokenHash, expiry, user.UserID);

  logAudit({ companyId: user.CompanyID, branchId: user.BranchID, userId: user.UserID, action: 'PASSWORD_RESET_REQUESTED', ip: req.ip });

  const link = `${publicBaseUrl(req)}/forgot-password.html?u=${encodeURIComponent(user.UserName)}&t=${resetToken}`;
  const result = await messaging.sendTemplate({
    companyId: user.CompanyID, code: 'PASSWORD_RESET', to: user.Email,
    vars: { name: user.FullName || user.UserName, token: resetToken, link },
    refType: 'Users', refId: user.UserID, sensitive: true
  });
  if (result.status !== 'Sent') {
    logAudit({ companyId: user.CompanyID, branchId: user.BranchID, userId: user.UserID, action: 'PASSWORD_RESET_NOT_DELIVERED', details: result.status, ip: req.ip });
  }
  res.json(genericResponse);
});

router.post('/reset-password', resetLimiter, (req, res) => {
  const { username, token, newPassword } = req.body;
  if (!username || !token || !newPassword) {
    return res.status(400).json({ error: 'username, token and newPassword are required' });
  }
  const pwProblem = checkPassword(newPassword);
  if (pwProblem) return res.status(400).json({ error: pwProblem });

  const user = db.prepare('SELECT * FROM Users WHERE UserName = ?').get(username);
  if (!user || !user.ResetTokenHash || !user.ResetTokenExpiry) {
    return res.status(400).json({ error: 'Invalid or expired reset token' });
  }
  if (new Date(user.ResetTokenExpiry).getTime() < Date.now()) {
    return res.status(400).json({ error: 'Reset token has expired. Please request a new one.' });
  }

  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  if (tokenHash !== user.ResetTokenHash) {
    return res.status(400).json({ error: 'Invalid or expired reset token' });
  }

  const newHash = bcrypt.hashSync(newPassword, 10);
  db.prepare(`UPDATE Users SET PasswordHash = ?, ResetTokenHash = NULL, ResetTokenExpiry = NULL,
              MustChangePassword = 0, FailedLogins = 0, LockedUntil = NULL, PasswordChangedAt = datetime('now') WHERE UserID = ?`)
    .run(newHash, user.UserID);

  logAudit({ companyId: user.CompanyID, branchId: user.BranchID, userId: user.UserID, action: 'PASSWORD_RESET_COMPLETED', ip: req.ip });

  res.json({ message: 'Password has been reset. You can now log in with your new password.' });
});

// ---- Change your own password (while logged in) ----
// The current password is required even though the caller is already
// authenticated: it stops someone changing the password on a machine the real
// user walked away from, and it's what people expect.
router.post('/change-password', requireAuth, resetLimiter, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'currentPassword and newPassword are required' });
  }
  const pwProblem = checkPassword(newPassword);
  if (pwProblem) return res.status(400).json({ error: pwProblem });
  if (currentPassword === newPassword) {
    return res.status(400).json({ error: 'The new password must be different from the current one' });
  }

  const user = db.prepare('SELECT * FROM Users WHERE UserID = ?').get(req.user.userId);
  if (!user || !bcrypt.compareSync(currentPassword, user.PasswordHash)) {
    logAudit({ companyId: req.user.companyId, branchId: req.user.branchId, userId: req.user.userId, action: 'PASSWORD_CHANGE_FAILED', ip: req.ip });
    return res.status(401).json({ error: 'Your current password is not correct' });
  }

  // Any outstanding reset token is cleared too - otherwise a token requested
  // before the change would still be usable afterwards.
  db.prepare(`UPDATE Users SET PasswordHash = ?, ResetTokenHash = NULL, ResetTokenExpiry = NULL,
              MustChangePassword = 0, PasswordChangedAt = datetime('now') WHERE UserID = ?`)
    .run(bcrypt.hashSync(newPassword, 10), user.UserID);

  logAudit({ companyId: user.CompanyID, branchId: user.BranchID, userId: user.UserID, action: 'PASSWORD_CHANGED', ip: req.ip });
  res.json({ message: 'Password changed. Use the new password next time you log in.' });
});

// ---- ROL-02: two-factor enrolment ----
// Finance and admin roles can (and for a real deployment, should) turn on TOTP.
const TWOFA_ROLES = ['Super Admin', 'Company Admin', 'Accountant'];
router.post('/2fa/setup', requireAuth, (req, res) => {
  if (!TWOFA_ROLES.includes(req.user.role)) return res.status(403).json({ error: 'Two-factor is for admin and finance roles' });
  const secret = totp.randomSecret();
  db.prepare('UPDATE Users SET TotpSecret = ?, TotpEnabled = 0 WHERE UserID = ?').run(secret, req.user.userId);
  res.json({ secret, otpauthUri: totp.otpauthUri(secret, req.user.userName || `user${req.user.userId}`) });
});
router.post('/2fa/enable', requireAuth, (req, res) => {
  const u = db.prepare('SELECT TotpSecret FROM Users WHERE UserID = ?').get(req.user.userId);
  if (!u || !u.TotpSecret) return res.status(400).json({ error: 'Start with 2FA setup first' });
  if (!totp.verify(u.TotpSecret, String(req.body.totp || '').trim())) return res.status(400).json({ error: 'That code is not valid - check the time on your phone and try again' });
  const codes = totp.recoveryCodes();
  db.prepare('UPDATE Users SET TotpEnabled = 1, RecoveryCodesJson = ? WHERE UserID = ?').run(JSON.stringify(codes), req.user.userId);
  logAudit({ companyId: req.user.companyId, userId: req.user.userId, action: 'ENABLE_2FA', ip: req.ip });
  res.json({ success: true, recoveryCodes: codes });
});
router.post('/2fa/disable', requireAuth, (req, res) => {
  const u = db.prepare('SELECT PasswordHash FROM Users WHERE UserID = ?').get(req.user.userId);
  if (!u || !bcrypt.compareSync(String(req.body.password || ''), u.PasswordHash)) return res.status(401).json({ error: 'Confirm your password to turn off two-factor' });
  db.prepare('UPDATE Users SET TotpEnabled = 0, TotpSecret = NULL, RecoveryCodesJson = NULL WHERE UserID = ?').run(req.user.userId);
  logAudit({ companyId: req.user.companyId, userId: req.user.userId, action: 'DISABLE_2FA', ip: req.ip });
  res.json({ success: true });
});

module.exports = { router, logAudit };
