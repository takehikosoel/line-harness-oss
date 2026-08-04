import { describe, expect, it } from 'vitest';
import { hashPassword, validatePasswordStrength, verifyPassword } from '../src/password.js';

describe('password', () => {
  it('hashes and verifies without reusing salts', async () => {
    const a = await hashPassword('abcdefghij');
    const b = await hashPassword('abcdefghij');
    expect(a).not.toBe(b);
    expect(await verifyPassword('abcdefghij', a)).toBe(true);
    expect(await verifyPassword('wrong-password', a)).toBe(false);
  });
  it.each(['', '$', 'pbkdf2$unknown$100000$AA==$AA=='])('rejects malformed hash %s', async (stored) => {
    await expect(verifyPassword('abcdefghij', stored)).resolves.toBe(false);
  });
  it('validates the length boundary', () => {
    expect(validatePasswordStrength('123456789')).not.toBeNull();
    expect(validatePasswordStrength('1234567890')).toBeNull();
  });
});
