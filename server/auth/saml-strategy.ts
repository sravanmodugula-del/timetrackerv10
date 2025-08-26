
import { Strategy as SamlStrategy } from 'passport-saml';
import { Strategy as LdapStrategy } from 'passport-ldapauth';
import { db } from '../db.js';

export const configureSamlStrategy = (passport: any) => {
  passport.use('saml', new SamlStrategy({
    callbackUrl: 'https://timetracker.fmb.com/saml/acs',
    entryPoint: process.env.SAML_ENTRY_POINT || 'https://timetracker.fmb.com/saml/sso',
    issuer: 'a0tt0vrnu3tt',
    audience: 'https://timetracker.fmb.com/saml/metadata',
    cert: process.env.SAML_CERT,
  }, async (profile: any, done: any) => {
    try {
      // Extract user info from SAML profile
      const email = profile.email || profile.nameID;
      const firstName = profile.firstName || profile.givenName;
      const lastName = profile.lastName || profile.surname;
      
      // Map SAML roles to application roles
      const samlRole = profile['http://schemas.microsoft.com/ws/2008/06/identity/claims/role'];
      const role = mapSamlRole(samlRole);
      
      // Create or update user
      const user = await db.user.upsert({
        where: { email },
        update: {
          firstName,
          lastName,
          role,
          lastLoginAt: new Date(),
        },
        create: {
          email,
          firstName,
          lastName,
          role,
          lastLoginAt: new Date(),
        },
      });
      
      return done(null, user);
    } catch (error) {
      return done(error, null);
    }
  }));
};

function mapSamlRole(samlRole: string): string {
  const roleMappings: Record<string, string> = {
    'TimeTracker-Admins': 'admin',
    'TimeTracker-Managers': 'manager',
    'TimeTracker-ProjectManagers': 'project_manager',
    'TimeTracker-Employees': 'employee'
  };
  
  return roleMappings[samlRole] || 'employee';
}
